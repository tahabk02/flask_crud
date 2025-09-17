import re
from sqlalchemy.exc import IntegrityError
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import logging
from flask_moment import Moment
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre-cle-secrete-super-secure-ici'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
moment = Moment(app)

# Configuration du logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/task_manager.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Task Manager startup')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.login_message_category = 'info'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    tasks = db.relationship('Task', backref='author', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        """Hash et stocke le mot de passe"""
        if len(password) < 6:
            raise ValueError("Le mot de passe doit contenir au moins 6 caractères")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Vérifie le mot de passe"""
        return check_password_hash(self.password_hash, password)
    
    def get_task_stats(self):
        """Retourne les statistiques des tâches de l'utilisateur"""
        total = len(self.tasks)
        completed = len([t for t in self.tasks if t.completed])
        pending = total - completed
        high_priority = len([t for t in self.tasks if t.priority == 'high' and not t.completed])
        pomodoro_sessions = sum(t.pomodoro_sessions for t in self.tasks)
        overdue = len([t for t in self.tasks if t.is_overdue()])
        
        return {
            'total': total,
            'completed': completed,
            'pending': pending,
            'high_priority': high_priority,
            'pomodoro_sessions': pomodoro_sessions,
            'overdue': overdue
        }

    def __repr__(self):
        return f'<User {self.username}>'

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False, index=True)
    priority = db.Column(db.String(20), default='medium', index=True)
    category = db.Column(db.String(50), default='general')
    is_pomodoro = db.Column(db.Boolean, default=False)
    pomodoro_duration = db.Column(db.Integer, default=25)  # en minutes
    break_duration = db.Column(db.Integer, default=5)     # en minutes
    pomodoro_sessions = db.Column(db.Integer, default=0)  # sessions complétées
    estimated_pomodoros = db.Column(db.Integer, default=4) # estimation
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def is_overdue(self):
        """Vérifie si la tâche est en retard"""
        if self.due_date and not self.completed:
            return datetime.utcnow() > self.due_date
        return False
    
    def get_priority_display(self):
        """Retourne l'affichage de la priorité avec emoji"""
        priority_map = {
            'high': '🔴 Élevée',
            'medium': '🟡 Moyenne',
            'low': '🟢 Basse'
        }
        return priority_map.get(self.priority, '🟡 Moyenne')
    
    def get_priority_class(self):
        """Retourne la classe CSS pour la priorité"""
        return {
            'high': 'danger',
            'medium': 'warning',
            'low': 'success'
        }.get(self.priority, 'secondary')
    
    def get_completion_percentage(self):
        """Pour les tâches Pomodoro, calcule le pourcentage d'avancement"""
        if not self.is_pomodoro or self.estimated_pomodoros == 0:
            return 0
        return min(100, (self.pomodoro_sessions / self.estimated_pomodoros) * 100)

    def get_time_remaining(self):
        """Retourne le temps restant jusqu'à l'échéance"""
        if not self.due_date:
            return None
        
        remaining = self.due_date - datetime.utcnow()
        if remaining.total_seconds() < 0:
            return "En retard"
        
        days = remaining.days
        hours = remaining.seconds // 3600
        
        if days > 0:
            return f"{days} jour{'s' if days > 1 else ''}"
        elif hours > 0:
            return f"{hours}h"
        else:
            return "Moins d'1h"

    def __repr__(self):
        return f'<Task {self.title}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Filtres de template personnalisés
@app.template_filter('datetime')
def datetime_filter(date):
    """Formate une date en français"""
    if date:
        return date.strftime('%d/%m/%Y à %H:%M')
    return ''

@app.template_filter('date')
def date_filter(date):
    """Formate une date courte"""
    if date:
        return date.strftime('%d/%m/%Y')
    return ''

@app.template_filter('date_input')
def date_input_filter(date):
    """Formate une date pour les inputs HTML"""
    if date:
        return date.strftime('%Y-%m-%d')
    return ''

# Context processors pour les templates
@app.context_processor
def inject_user_stats():
    """Injecte les statistiques utilisateur dans tous les templates"""
    if current_user.is_authenticated:
        return dict(user_stats=current_user.get_task_stats())
    return dict()

# Routes principales
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Validation
            errors = []
            
            if not username or len(username) < 3:
                errors.append("Le nom d'utilisateur doit contenir au moins 3 caractères.")
            elif len(username) > 80:
                errors.append("Le nom d'utilisateur ne peut pas dépasser 80 caractères.")
            elif not username.replace('_', '').replace('-', '').isalnum():
                errors.append("Le nom d'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores.")
            
            # Vérif email
            regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
            if not email or not re.match(regex, email):
                errors.append("Veuillez entrer une adresse email valide.")
            elif len(email) > 120:
                errors.append("L'adresse email est trop longue.")
            
            # Vérif password
            if not password or len(password) < 6:
                errors.append("Le mot de passe doit contenir au moins 6 caractères.")
            elif password != confirm_password:
                errors.append("Les mots de passe ne correspondent pas.")
            
            # Vérifier si l'utilisateur existe déjà
            if User.query.filter_by(username=username).first():
                errors.append("Ce nom d'utilisateur est déjà pris.")
            
            if User.query.filter_by(email=email).first():
                errors.append("Cette adresse email est déjà utilisée.")
            
            if errors:
                for error in errors:
                    flash(error, "danger")
                return render_template("register.html", 
                                     username=username, 
                                     email=email)
            
            # Créer le nouvel utilisateur
            user = User(username=username, email=email)
            user.set_password(password)
            
            # Le premier utilisateur devient admin
            if User.query.count() == 0:
                user.is_admin = True
                app.logger.info(f"Premier utilisateur créé: {username} (admin)")
            
            db.session.add(user)
            db.session.commit()
            
            app.logger.info(f"Nouvel utilisateur enregistré: {username}")
            flash(f"Inscription réussie! Bienvenue {username}.", "success")
            
            # 🔑 Auto-login direct après inscription
            login_user(user)
            return redirect(url_for("dashboard"))
            
        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f"Erreur d'intégrité DB: {str(e)}")
            flash("Erreur base de données. Cet utilisateur existe peut-être déjà.", "danger")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de l'inscription: {str(e)}")
            flash("Une erreur est survenue lors de l'inscription. Veuillez réessayer.", "danger")
    
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            remember = request.form.get('remember_me', False)
            
            if not username or not password:
                flash('Veuillez remplir tous les champs.', 'warning')
                return render_template('login.html', username=username)
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                # Mettre à jour la dernière connexion
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                login_user(user, remember=remember)
                app.logger.info(f'Connexion réussie pour: {username}')
                flash(f'Bienvenue {username}!', 'success')
                
                # Redirection vers la page demandée ou tableau de bord
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                app.logger.warning(f'Tentative de connexion échouée pour: {username}')
                flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
                
        except Exception as e:
            app.logger.error(f'Erreur lors de la connexion: {str(e)}')
            flash('Une erreur est survenue lors de la connexion.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    app.logger.info(f'Déconnexion de: {username}')
    flash('Déconnexion réussie. À bientôt!', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin and request.args.get('admin') == '1':
        return redirect(url_for('admin_dashboard'))
    
    # Récupérer les tâches avec tri par défaut
    sort_by = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc')
    filter_status = request.args.get('status', 'all')
    filter_priority = request.args.get('priority', 'all')
    search = request.args.get('search', '').strip()
    
    query = Task.query.filter_by(user_id=current_user.id)
    
    # Filtrage par recherche
    if search:
        query = query.filter(
            db.or_(
                Task.title.ilike(f'%{search}%'),
                Task.description.ilike(f'%{search}%')
            )
        )
    
    # Filtrage par statut
    if filter_status == 'completed':
        query = query.filter_by(completed=True)
    elif filter_status == 'pending':
        query = query.filter_by(completed=False)
    elif filter_status == 'overdue':
        query = query.filter(
            Task.due_date < datetime.utcnow(),
            Task.completed == False
        )
    
    # Filtrage par priorité
    if filter_priority in ['high', 'medium', 'low']:
        query = query.filter_by(priority=filter_priority)
    
    # Tri
    if sort_by == 'priority':
        priority_order = {'high': 3, 'medium': 2, 'low': 1}
        tasks = query.all()
        tasks.sort(key=lambda x: priority_order.get(x.priority, 0), 
                  reverse=(order == 'desc'))
    elif sort_by == 'due_date':
        if order == 'desc':
            query = query.order_by(Task.due_date.desc().nullslast())
        else:
            query = query.order_by(Task.due_date.asc().nullslast())
        tasks = query.all()
    else:
        if hasattr(Task, sort_by):
            if order == 'desc':
                query = query.order_by(getattr(Task, sort_by).desc())
            else:
                query = query.order_by(getattr(Task, sort_by))
        else:
            query = query.order_by(Task.created_at.desc())
        tasks = query.all()
    
    return render_template('dashboard.html', 
                         tasks=tasks,
                         current_sort=sort_by,
                         current_order=order,
                         current_status=filter_status,
                         current_priority=filter_priority,
                         search=search)

@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        try:
            # Récupération et validation des données
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            priority = request.form.get('priority', 'medium')
            category = request.form.get('category', 'general').strip()
            is_pomodoro = 'is_pomodoro' in request.form
            due_date_str = request.form.get('due_date', '')
            
            # Validation côté serveur
            errors = []
            
            if not title:
                errors.append('Le titre de la tâche est obligatoire.')
            elif len(title) > 100:
                errors.append('Le titre ne peut pas dépasser 100 caractères.')
            
            if priority not in ['low', 'medium', 'high']:
                errors.append('Priorité invalide.')
                priority = 'medium'
            
            if description and len(description) > 1000:
                errors.append('La description ne peut pas dépasser 1000 caractères.')
            
            if category and len(category) > 50:
                errors.append('La catégorie ne peut pas dépasser 50 caractères.')
            
            # Validation de la date d'échéance
            due_date = None
            if due_date_str:
                try:
                    due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
                    if due_date.date() < datetime.now().date():
                        errors.append('La date d\'échéance ne peut pas être dans le passé.')
                except ValueError:
                    errors.append('Format de date invalide.')
            
            # Validation des paramètres Pomodoro
            pomodoro_duration = 25
            break_duration = 5
            estimated_pomodoros = 4
            
            if is_pomodoro:
                try:
                    pomodoro_duration = int(request.form.get('pomodoro_duration', 25))
                    break_duration = int(request.form.get('break_duration', 5))
                    estimated_pomodoros = int(request.form.get('estimated_pomodoros', 4))
                    
                    if not (5 <= pomodoro_duration <= 60):
                        errors.append('La durée de travail doit être entre 5 et 60 minutes.')
                        pomodoro_duration = 25
                    
                    if not (1 <= break_duration <= 30):
                        errors.append('La durée de pause doit être entre 1 et 30 minutes.')
                        break_duration = 5
                    
                    if not (1 <= estimated_pomodoros <= 20):
                        errors.append('Le nombre estimé de sessions doit être entre 1 et 20.')
                        estimated_pomodoros = 4
                        
                except (ValueError, TypeError):
                    errors.append('Les paramètres Pomodoro doivent être des nombres valides.')
                    pomodoro_duration = 25
                    break_duration = 5
                    estimated_pomodoros = 4
            
            # Si des erreurs existent, les afficher et recharger le formulaire
            if errors:
                for error in errors:
                    flash(error, 'danger')
                return render_template('add_task.html', 
                                     title=title, 
                                     description=description, 
                                     priority=priority,
                                     category=category,
                                     is_pomodoro=is_pomodoro,
                                     pomodoro_duration=pomodoro_duration,
                                     break_duration=break_duration,
                                     estimated_pomodoros=estimated_pomodoros,
                                     due_date=due_date_str)
            
            # Création de la tâche
            task = Task(
                title=title,
                description=description if description else None,
                priority=priority,
                category=category,
                is_pomodoro=is_pomodoro,
                pomodoro_duration=pomodoro_duration,
                break_duration=break_duration,
                estimated_pomodoros=estimated_pomodoros,
                due_date=due_date,
                user_id=current_user.id
            )
            
            db.session.add(task)
            db.session.commit()
            
            app.logger.info(f'Nouvelle tâche créée par {current_user.username}: {title}')
            flash(f'Tâche "{title}" ajoutée avec succès!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erreur lors de la création de la tâche: {str(e)}')
            flash('Une erreur est survenue lors de la création de la tâche. Veuillez réessayer.', 'danger')
            return render_template('add_task.html')
    
    return render_template('add_task.html')

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Vérification des permissions
    if task.user_id != current_user.id and not current_user.is_admin:
        flash('Accès non autorisé à cette tâche.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Récupération des données
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            priority = request.form.get('priority', 'medium')
            category = request.form.get('category', 'general').strip()
            is_pomodoro = 'is_pomodoro' in request.form
            due_date_str = request.form.get('due_date', '')
            
            # Validation
            errors = []
            
            if not title:
                errors.append('Le titre de la tâche est obligatoire.')
            elif len(title) > 100:
                errors.append('Le titre ne peut pas dépasser 100 caractères.')
            
            if priority not in ['low', 'medium', 'high']:
                errors.append('Priorité invalide.')
                priority = task.priority
            
            if description and len(description) > 1000:
                errors.append('La description ne peut pas dépasser 1000 caractères.')
                
            if category and len(category) > 50:
                errors.append('La catégorie ne peut pas dépasser 50 caractères.')
            
            # Validation de la date d'échéance
            due_date = None
            if due_date_str:
                try:
                    due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
                    if due_date.date() < datetime.now().date():
                        errors.append('La date d\'échéance ne peut pas être dans le passé.')
                except ValueError:
                    errors.append('Format de date invalide.')
            
            # Validation Pomodoro
            pomodoro_duration = task.pomodoro_duration
            break_duration = task.break_duration
            estimated_pomodoros = task.estimated_pomodoros
            
            if is_pomodoro:
                try:
                    pomodoro_duration = int(request.form.get('pomodoro_duration', task.pomodoro_duration))
                    break_duration = int(request.form.get('break_duration', task.break_duration))
                    estimated_pomodoros = int(request.form.get('estimated_pomodoros', task.estimated_pomodoros))
                    
                    if not (5 <= pomodoro_duration <= 60):
                        errors.append('La durée de travail doit être entre 5 et 60 minutes.')
                        pomodoro_duration = task.pomodoro_duration
                    
                    if not (1 <= break_duration <= 30):
                        errors.append('La durée de pause doit être entre 1 et 30 minutes.')
                        break_duration = task.break_duration
                    
                    if not (1 <= estimated_pomodoros <= 20):
                        errors.append('Le nombre estimé de sessions doit être entre 1 et 20.')
                        estimated_pomodoros = task.estimated_pomodoros
                        
                except (ValueError, TypeError):
                    errors.append('Les paramètres Pomodoro doivent être des nombres valides.')
            
            if errors:
                for error in errors:
                    flash(error, 'danger')
                return render_template('edit_task.html', task=task)
            
            # Mise à jour
            task.title = title
            task.description = description if description else None
            task.priority = priority
            task.category = category
            task.is_pomodoro = is_pomodoro
            task.pomodoro_duration = pomodoro_duration
            task.break_duration = break_duration
            task.estimated_pomodoros = estimated_pomodoros
            task.due_date = due_date
            task.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            app.logger.info(f'Tâche {task_id} mise à jour par {current_user.username}')
            flash(f'Tâche "{title}" mise à jour avec succès!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erreur lors de la mise à jour de la tâche {task_id}: {str(e)}')
            flash('Une erreur est survenue lors de la mise à jour.', 'danger')
    
    return render_template('edit_task.html', task=task)

@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.user_id != current_user.id and not current_user.is_admin:
        flash('Accès non autorisé.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        task_title = task.title
        db.session.delete(task)
        db.session.commit()
        
        app.logger.info(f'Tâche {task_id} supprimée par {current_user.username}')
        flash(f'Tâche "{task_title}" supprimée avec succès!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors de la suppression de la tâche {task_id}: {str(e)}')
        flash('Erreur lors de la suppression.', 'danger')
    
    return redirect(url_for('admin_dashboard') if current_user.is_admin and request.referrer and 'admin' in request.referrer else url_for('dashboard'))

@app.route('/toggle_task/<int:task_id>', methods=['POST'])
@login_required
def toggle_task(task_id):
    try:
        task = Task.query.get_or_404(task_id)
        
        if task.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Accès non autorisé'}), 403
        
        task.completed = not task.completed
        task.updated_at = datetime.utcnow()
        db.session.commit()
        
        app.logger.info(f'Tâche {task_id} {"complétée" if task.completed else "rouverte"} par {current_user.username}')
        return jsonify({
            'completed': task.completed,
            'message': f'Tâche {"complétée" if task.completed else "rouverte"} avec succès'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors du basculement de la tâche {task_id}: {str(e)}')
        return jsonify({'error': 'Erreur lors de la mise à jour'}), 500

@app.route('/pomodoro/<int:task_id>')
@login_required
def pomodoro_timer(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.user_id != current_user.id and not current_user.is_admin:
        flash('Accès non autorisé.', 'danger')
        return redirect(url_for('dashboard'))
    
    if not task.is_pomodoro:
        flash('Cette tâche n\'est pas configurée pour le Pomodoro.', 'warning')
        return redirect(url_for('dashboard'))
    
    return render_template('pomodoro_timer.html', task=task)

@app.route('/complete_pomodoro/<int:task_id>', methods=['POST'])
@login_required
def complete_pomodoro(task_id):
    try:
        task = Task.query.get_or_404(task_id)
        
        if task.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Accès non autorisé'}), 403
        
        task.pomodoro_sessions += 1
        task.updated_at = datetime.utcnow()
        
        # Auto-compléter si on atteint le nombre estimé de sessions
        if task.pomodoro_sessions >= task.estimated_pomodoros and not task.completed:
            task.completed = True
        
        db.session.commit()
        
        app.logger.info(f'Session Pomodoro complétée pour la tâche {task_id} par {current_user.username}')
        return jsonify({
            'sessions': task.pomodoro_sessions,
            'completed': task.completed,
            'percentage': task.get_completion_percentage(),
            'message': f'Session Pomodoro #{task.pomodoro_sessions} complétée!'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors de la complétion Pomodoro {task_id}: {str(e)}')
        return jsonify({'error': 'Erreur lors de la mise à jour'}), 500

# Routes d'administration
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Accès administrateur requis.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Statistiques globales
    total_users = User.query.count()
    total_tasks = Task.query.count()
    completed_tasks = Task.query.filter_by(completed=True).count()
    pending_tasks = total_tasks - completed_tasks
    total_pomodoro_sessions = db.session.query(db.func.sum(Task.pomodoro_sessions)).scalar() or 0
    
    # Utilisateurs récents
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    # Tâches récentes
    recent_tasks = Task.query.order_by(Task.created_at.desc()).limit(10).all()
    
    # Tâches en retard
    overdue_tasks = Task.query.filter(
        Task.due_date < datetime.utcnow(),
        Task.completed == False
    ).all()
    
    # Statistiques par priorité
    priority_stats = {
        'high': Task.query.filter_by(priority='high', completed=False).count(),
        'medium': Task.query.filter_by(priority='medium', completed=False).count(),
        'low': Task.query.filter_by(priority='low', completed=False).count()
    }
    
    stats = {
        'total_users': total_users,
        'total_tasks': total_tasks,
        'completed_tasks': completed_tasks,
        'pending_tasks': pending_tasks,
        'total_pomodoro_sessions': total_pomodoro_sessions,
        'overdue_tasks': len(overdue_tasks),
        'priority_stats': priority_stats
    }
    
    return render_template('admin_dashboard.html', 
                         stats=stats,
                         recent_users=recent_users,
                         recent_tasks=recent_tasks,
                         overdue_tasks=overdue_tasks)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Accès administrateur requis.', 'danger')
        return redirect(url_for('dashboard'))
    
    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    query = User.query
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )
    
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin_users.html', users=users, search=search)

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash('Accès administrateur requis.', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Vous ne pouvez pas supprimer votre propre compte.', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        app.logger.warning(f'Utilisateur {username} supprimé par l\'admin {current_user.username}')
        flash(f'Utilisateur "{username}" supprimé avec succès!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors de la suppression de l\'utilisateur {user_id}: {str(e)}')
        flash('Erreur lors de la suppression.', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/toggle_admin/<int:user_id>')
@login_required
def admin_toggle_admin(user_id):
    if not current_user.is_admin:
        flash('Accès administrateur requis.', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Vous ne pouvez pas modifier vos propres privilèges d\'administrateur.', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        user.is_admin = not user.is_admin
        db.session.commit()
        
        status = 'administrateur' if user.is_admin else 'utilisateur standard'
        app.logger.info(f'Statut de {user.username} changé en {status} par {current_user.username}')
        flash(f'Statut de "{user.username}" changé en {status}!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors de la modification du statut utilisateur {user_id}: {str(e)}')
        flash('Erreur lors de la modification du statut.', 'danger')
    
    return redirect(url_for('admin_users'))

# Routes API
@app.route('/api/stats')
@login_required
def api_stats():
    """API pour récupérer les statistiques utilisateur"""
    if current_user.is_admin and request.args.get('global') == '1':
        # Statistiques globales pour admin
        stats = {
            'total_users': User.query.count(),
            'total_tasks': Task.query.count(),
            'completed_tasks': Task.query.filter_by(completed=True).count(),
            'pending_tasks': Task.query.filter_by(completed=False).count(),
            'overdue_tasks': Task.query.filter(
                Task.due_date < datetime.utcnow(),
                Task.completed == False
            ).count(),
            'pomodoro_sessions': db.session.query(db.func.sum(Task.pomodoro_sessions)).scalar() or 0
        }
    else:
        # Statistiques utilisateur
        stats = current_user.get_task_stats()
    
    return jsonify(stats)

@app.route('/api/tasks/bulk_update', methods=['POST'])
@login_required
def api_bulk_update_tasks():
    """API pour la mise à jour en masse des tâches"""
    try:
        data = request.get_json()
        task_ids = data.get('task_ids', [])
        action = data.get('action')
        
        if not task_ids or not action:
            return jsonify({'error': 'Paramètres manquants'}), 400
        
        # Vérifier que toutes les tâches appartiennent à l'utilisateur
        tasks = Task.query.filter(Task.id.in_(task_ids)).all()
        
        for task in tasks:
            if task.user_id != current_user.id and not current_user.is_admin:
                return jsonify({'error': 'Accès non autorisé'}), 403
        
        updated_count = 0
        
        if action == 'complete':
            for task in tasks:
                if not task.completed:
                    task.completed = True
                    task.updated_at = datetime.utcnow()
                    updated_count += 1
        
        elif action == 'uncomplete':
            for task in tasks:
                if task.completed:
                    task.completed = False
                    task.updated_at = datetime.utcnow()
                    updated_count += 1
        
        elif action == 'delete':
            for task in tasks:
                db.session.delete(task)
                updated_count += 1
        
        elif action == 'set_priority':
            priority = data.get('priority', 'medium')
            if priority in ['low', 'medium', 'high']:
                for task in tasks:
                    task.priority = priority
                    task.updated_at = datetime.utcnow()
                    updated_count += 1
        
        db.session.commit()
        
        app.logger.info(f'Mise à jour en masse de {updated_count} tâches par {current_user.username}')
        return jsonify({
            'success': True,
            'updated_count': updated_count,
            'message': f'{updated_count} tâche(s) mise(s) à jour'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors de la mise à jour en masse: {str(e)}')
        return jsonify({'error': 'Erreur lors de la mise à jour'}), 500

# Routes utilitaires
@app.route('/profile')
@login_required
def profile():
    """Page de profil utilisateur"""
    return render_template('profile.html')

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Mise à jour du profil utilisateur"""
    try:
        email = request.form.get('email', '').strip().lower()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        errors = []
        
        # Validation email
        if not email or '@' not in email:
            errors.append('Veuillez entrer une adresse email valide.')
        elif len(email) > 120:
            errors.append('L\'adresse email est trop longue.')
        elif email != current_user.email and User.query.filter_by(email=email).first():
            errors.append('Cette adresse email est déjà utilisée.')
        
        # Validation changement de mot de passe
        if new_password:
            if not current_password:
                errors.append('Mot de passe actuel requis pour changer le mot de passe.')
            elif not current_user.check_password(current_password):
                errors.append('Mot de passe actuel incorrect.')
            elif len(new_password) < 6:
                errors.append('Le nouveau mot de passe doit contenir au moins 6 caractères.')
            elif new_password != confirm_password:
                errors.append('Les nouveaux mots de passe ne correspondent pas.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('profile.html')
        
        # Mise à jour
        current_user.email = email
        
        if new_password:
            current_user.set_password(new_password)
            flash('Mot de passe mis à jour avec succès!', 'success')
        
        db.session.commit()
        
        app.logger.info(f'Profil mis à jour pour {current_user.username}')
        flash('Profil mis à jour avec succès!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors de la mise à jour du profil: {str(e)}')
        flash('Erreur lors de la mise à jour du profil.', 'danger')
    
    return redirect(url_for('profile'))

# Gestionnaires d'erreur
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# Commandes CLI pour l'initialisation
@app.cli.command()
def init_db():
    """Initialise la base de données"""
    db.create_all()
    print("Base de données initialisée!")

@app.cli.command()
def create_admin():
    """Crée un compte administrateur"""
    username = input("Nom d'utilisateur: ")
    email = input("Email: ")
    password = input("Mot de passe: ")
    
    if User.query.filter_by(username=username).first():
        print("Ce nom d'utilisateur existe déjà!")
        return
    
    if User.query.filter_by(email=email).first():
        print("Cette adresse email existe déjà!")
        return
    
    user = User(username=username, email=email, is_admin=True)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    print(f"Administrateur '{username}' créé avec succès!")

# Point d'entrée principal
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)