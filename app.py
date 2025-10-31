import os
import json
import csv
from io import StringIO
from datetime import datetime, date, timedelta
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, DateTimeField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, Length, Optional, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, and_, or_

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(UserMixin, db.Model):
    """User accounts for Admin/Receptionist, Doctors, and Pharmacists"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    emp_no = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120))
    role = db.Column(db.String(20), nullable=False, default='receptionist')  # admin, receptionist, doctor, pharmacist
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    doctor_profile = db.relationship('Doctor', backref='user', uselist=False, cascade='all, delete-orphan')
    appointments_created = db.relationship('Appointment', backref='creator', foreign_keys='Appointment.created_by')
    
    @property
    def username(self):
        return self.emp_no
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.emp_no} ({self.role})>'

class MedicineStock(db.Model):
    """Track medicine stock levels"""
    __tablename__ = 'medicine_stock'
    
    id = db.Column(db.Integer, primary_key=True)
    medicine_name = db.Column(db.String(120), nullable=False, unique=True)
    current_stock = db.Column(db.Integer, default=0)
    min_stock_level = db.Column(db.Integer, default=10)
    unit_price = db.Column(db.Float, default=0)
    expiry_date = db.Column(db.Date)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_low_stock(self):
        return self.current_stock <= self.min_stock_level
    
    def days_to_expiry(self):
        if self.expiry_date:
            return (self.expiry_date - date.today()).days
        return None
    
    def is_expired(self):
        if self.expiry_date:
            return self.expiry_date < date.today()
        return False
    
    def __repr__(self):
        return f'<MedicineStock {self.medicine_name}>'

class Doctor(db.Model):
    """Doctor profiles linked to User accounts"""
    __tablename__ = 'doctors'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    specialization = db.Column(db.String(100), nullable=False, index=True)
    gender = db.Column(db.String(20))
    location = db.Column(db.String(200), index=True)
    phone = db.Column(db.String(20))
    availability = db.Column(db.Text)
    consultation_fee = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    appointments = db.relationship('Appointment', backref='doctor', lazy='dynamic', cascade='all, delete-orphan')
    queue_entries = db.relationship('QueueEntry', backref='doctor', lazy='dynamic')
    prescriptions = db.relationship('Prescription', backref='doctor', lazy='dynamic')
    
    @property
    def name(self):
        return self.user.full_name if self.user else 'Unknown'
    
    @property
    def email(self):
        return self.user.email if self.user else ''
    
    def get_availability_dict(self):
        """Parse availability JSON"""
        try:
            return json.loads(self.availability) if self.availability else {}
        except:
            return {}
    
    def __repr__(self):
        return f'<Doctor {self.name} - {self.specialization}>'


class Patient(db.Model):
    """Patient records"""
    __tablename__ = 'patients'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False, index=True)
    email = db.Column(db.String(120))
    gender = db.Column(db.String(20))
    age = db.Column(db.Integer)
    address = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    appointments = db.relationship('Appointment', backref='patient', lazy='dynamic')
    queue_entries = db.relationship('QueueEntry', backref='patient', lazy='dynamic')
    prescriptions = db.relationship('Prescription', backref='patient', lazy='dynamic')
    
    def __repr__(self):
        return f'<Patient {self.name}>'


class Appointment(db.Model):
    """Appointment bookings"""
    __tablename__ = 'appointments'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False, index=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False, index=True)
    appointment_datetime = db.Column(db.DateTime, nullable=False, index=True)
    status = db.Column(db.String(20), default='Booked', index=True)
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Appointment {self.id} - {self.status}>'


class QueueEntry(db.Model):
    """Walk-in patient queue management"""
    __tablename__ = 'queue_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=True, index=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=True, index=True)
    queue_number = db.Column(db.Integer, nullable=False)
    queue_date = db.Column(db.Date, nullable=False, index=True, default=date.today)
    status = db.Column(db.String(20), default='Waiting', index=True)  # Waiting, With Doctor, Completed, Canceled
    priority = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # For anonymous walk-ins
    walk_in_name = db.Column(db.String(120))
    walk_in_phone = db.Column(db.String(20))
    
    def get_patient_name(self):
        """Get patient name (registered or walk-in)"""
        return self.patient.name if self.patient else self.walk_in_name
    
    def get_patient_phone(self):
        """Get patient phone (registered or walk-in)"""
        return self.patient.phone if self.patient else self.walk_in_phone
    
    def __repr__(self):
        return f'<QueueEntry #{self.queue_number} - {self.status}>'


class Prescription(db.Model):
    """Prescription records for pharmacy workflow"""
    __tablename__ = 'prescriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=True, index=True)  # Changed to nullable=True
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False, index=True)
    queue_entry_id = db.Column(db.Integer, db.ForeignKey('queue_entries.id'), nullable=True)
    medication_details = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Issued', index=True)
    
    # For walk-in patients without registration
    walk_in_name = db.Column(db.String(120))
    walk_in_phone = db.Column(db.String(20))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    dispensed_at = db.Column(db.DateTime)
    dispensed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    queue_entry = db.relationship('QueueEntry', backref='prescriptions')
    dispenser = db.relationship('User', foreign_keys=[dispensed_by])
    
    def get_patient_name(self):
        """Get patient name (registered or walk-in)"""
        return self.patient.name if self.patient else self.walk_in_name
    
    def get_patient_phone(self):
        """Get patient phone (registered or walk-in)"""
        return self.patient.phone if self.patient else self.walk_in_phone
    
    def __repr__(self):
        return f'<Prescription {self.id} - {self.status}>'



# ============================================================================
# AUTHENTICATION & AUTHORIZATION
# ============================================================================

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(user_id))


def admin_required(f):
    """Decorator for admin-only routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def receptionist_required(f):
    """Decorator for receptionist/admin routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'receptionist']:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def doctor_required(f):
    """Decorator for doctor-only routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'doctor':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def pharmacist_required(f):
    """Decorator for pharmacist-only routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'pharmacist':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# FORMS
# ============================================================================

class LoginForm(FlaskForm):
    """Login form"""
    emp_no = StringField('Employee No.', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])


class ChangePasswordForm(FlaskForm):
    """Change password form for doctors"""
    old_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])


class DoctorForm(FlaskForm):
    """Doctor profile form"""
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=120)])
    emp_no = StringField('Employee No.', validators=[DataRequired(), Length(max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    specialization = StringField('Specialization', validators=[DataRequired(), Length(max=100)])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[Optional()])
    location = StringField('Location/Clinic', validators=[Optional(), Length(max=200)])
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    consultation_fee = IntegerField('Consultation Fee (₹)', validators=[Optional()])
    availability = TextAreaField('Availability (e.g., Mon 09:00-12:00, Wed 14:00-17:00)', validators=[Optional()])


class DoctorEditForm(FlaskForm):
    """Doctor edit form (without password)"""
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=120)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    specialization = StringField('Specialization', validators=[DataRequired(), Length(max=100)])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[Optional()])
    location = StringField('Location/Clinic', validators=[Optional(), Length(max=200)])
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    consultation_fee = IntegerField('Consultation Fee (₹)', validators=[Optional()])
    availability = TextAreaField('Availability', validators=[Optional()])


class PatientForm(FlaskForm):
    """Patient registration form"""
    name = StringField('Full Name', validators=[DataRequired(), Length(max=120)])
    phone = StringField('Phone Number', validators=[DataRequired(), Length(max=20)])
    email = StringField('Email', validators=[Optional(), Email()])
    gender = SelectField('Gender', choices=[('', 'Select'), ('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[Optional()])
    age = IntegerField('Age', validators=[Optional()])
    address = TextAreaField('Address', validators=[Optional()])
    notes = TextAreaField('Medical Notes', validators=[Optional()])


class QueueForm(FlaskForm):
    """Queue entry form"""
    patient_id = SelectField('Select Existing Patient', coerce=int, validators=[Optional()])
    walk_in_name = StringField('Walk-in Name', validators=[Optional(), Length(max=120)])
    walk_in_phone = StringField('Walk-in Phone', validators=[Optional(), Length(max=20)])
    doctor_id = SelectField('Assign to Doctor', coerce=int, validators=[Optional()])
    priority = SelectField('Priority', choices=[(0, 'Normal'), (1, 'Urgent')], coerce=int, validators=[Optional()])
    notes = TextAreaField('Notes', validators=[Optional()])


class PrescriptionForm(FlaskForm):
    """Prescription form"""
    medication_details = TextAreaField('Prescription Details', validators=[DataRequired()])


class PharmacistForm(FlaskForm):
    """Pharmacist account form"""
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=120)])
    emp_no = StringField('Employee No.', validators=[DataRequired(), Length(max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    email = StringField('Email', validators=[DataRequired(), Email()])


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def next_queue_number_for_today(doctor_id=None):
    """Generate next queue number for today"""
    today = date.today()
    query = QueueEntry.query.filter_by(queue_date=today)
    if doctor_id:
        query = query.filter_by(doctor_id=doctor_id)
    max_num = query.with_entities(func.max(QueueEntry.queue_number)).scalar()
    return (max_num or 0) + 1


def get_dashboard_stats():
    """Calculate dashboard statistics"""
    today = date.today()
    now = datetime.now()
    
    stats = {
        'today_appointments': Appointment.query.filter(
            func.date(Appointment.appointment_datetime) == today
        ).count(),
        'today_queue': QueueEntry.query.filter_by(queue_date=today).count(),
        'waiting_queue': QueueEntry.query.filter_by(
            queue_date=today, status='Waiting'
        ).count(),
        'active_doctors': Doctor.query.filter_by(is_active=True).count(),
        'total_patients': Patient.query.count(),
        'completed_today': QueueEntry.query.filter_by(
            queue_date=today, status='Completed'
        ).count(),
        'pending_prescriptions': Prescription.query.filter_by(status='Issued').count(),
    }
    
    return stats


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return render_template('errors/500.html'), 500


@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    return render_template('errors/403.html'), 403


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - redirects based on role"""
    if current_user.is_authenticated:
        if current_user.role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif current_user.role == 'pharmacist':
            return redirect(url_for('pharmacy'))
        else:
            return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(emp_no=form.emp_no.data).first()
        
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact administrator.', 'danger')
                return redirect(url_for('login'))
            
            login_user(user)
            flash(f'Welcome back, {user.full_name or user.emp_no}!', 'success')
            
            # Role-based redirect
            if user.role == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif user.role == 'pharmacist':
                return redirect(url_for('pharmacy'))
            else:
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid Employee No. or password. Please try again.', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Logout current user"""
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password for current user"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Your password has been changed successfully!', 'success')
            
            if current_user.role == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif current_user.role == 'pharmacist':
                return redirect(url_for('pharmacy'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Current password is incorrect.', 'danger')
    
    return render_template('change_password.html', form=form)


# ============================================================================
# ADMIN/RECEPTIONIST ROUTES
# ============================================================================

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard - role-based redirect"""
    if current_user.role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    elif current_user.role == 'pharmacist':
        return redirect(url_for('pharmacy'))
    
    # Admin/Receptionist dashboard
    stats = get_dashboard_stats()
    
    today = date.today()
    today_appointments = Appointment.query.filter(
        func.date(Appointment.appointment_datetime) == today
    ).order_by(Appointment.appointment_datetime).all()
    
    current_queue = QueueEntry.query.filter_by(
        queue_date=today
    ).order_by(QueueEntry.queue_number).all()
    
    return render_template('dashboard.html',
                         stats=stats,
                         today_appointments=today_appointments,
                         current_queue=current_queue)


@app.route('/doctors')
@login_required
@receptionist_required
def doctors():
    """List all doctors"""
    search = request.args.get('search', '')
    specialization = request.args.get('specialization', '')
    
    query = Doctor.query.join(User)
    
    if search:
        query = query.filter(
            or_(
                User.full_name.ilike(f'%{search}%'),
                Doctor.specialization.ilike(f'%{search}%')
            )
        )
    
    if specialization:
        query = query.filter(Doctor.specialization.ilike(f'%{specialization}%'))
    
    doctors_list = query.order_by(User.full_name).all()
    
    specializations = db.session.query(Doctor.specialization).distinct().all()
    specializations = [s[0] for s in specializations if s[0]]
    
    return render_template('doctors.html',
                         doctors=doctors_list,
                         specializations=specializations,
                         search=search,
                         selected_spec=specialization)


@app.route('/doctors/new', methods=['GET', 'POST'])
@login_required
@admin_required
def doctor_new():
    """Create new doctor account"""
    form = DoctorForm()
    
    if form.validate_on_submit():
        try:
            # Check if emp_no or email already exists
            existing_user = User.query.filter(
                or_(User.emp_no == form.emp_no.data, User.email == form.email.data)
            ).first()
            
            if existing_user:
                flash('Employee No. or Email already exists.', 'danger')
                return render_template('doctor_form.html', form=form, title='Add New Doctor')
            
            # Create user account
            new_user = User(
                emp_no=form.emp_no.data,
                email=form.email.data,
                full_name=form.full_name.data,
                role='doctor'
            )
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.flush()
            
            # Create doctor profile
            new_doctor = Doctor(
                user_id=new_user.id,
                specialization=form.specialization.data,
                gender=form.gender.data,
                location=form.location.data,
                phone=form.phone.data,
                consultation_fee=form.consultation_fee.data or 0,
                availability=form.availability.data
            )
            db.session.add(new_doctor)
            db.session.commit()
            
            flash(f'Doctor {new_user.full_name} created successfully! Login: {form.emp_no.data} | Password: {form.password.data}', 'success')
            return redirect(url_for('doctors'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating doctor account. Please try again.', 'danger')
            app.logger.error(f'Doctor create error: {str(e)}')
    
    return render_template('doctor_form.html', form=form, title='Add New Doctor')


@app.route('/doctors/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def doctor_edit(id):
    """Edit doctor profile"""
    doctor = Doctor.query.get_or_404(id)
    form = DoctorEditForm(obj=doctor)
    
    if form.validate_on_submit():
        try:
            doctor.user.full_name = form.full_name.data
            doctor.user.email = form.email.data
            doctor.specialization = form.specialization.data
            doctor.gender = form.gender.data
            doctor.location = form.location.data
            doctor.phone = form.phone.data
            doctor.consultation_fee = form.consultation_fee.data or 0
            doctor.availability = form.availability.data
            
            db.session.commit()
            flash(f'Doctor {doctor.name} updated successfully!', 'success')
            return redirect(url_for('doctors'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating doctor. Please try again.', 'danger')
            app.logger.error(f'Doctor update error: {str(e)}')
    
    # Pre-fill form
    form.full_name.data = doctor.user.full_name
    form.email.data = doctor.user.email
    
    return render_template('doctor_edit_form.html', form=form, doctor=doctor, title='Edit Doctor')


@app.route('/doctors/<int:id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def doctor_toggle_active(id):
    """Toggle doctor active status"""
    doctor = Doctor.query.get_or_404(id)
    
    try:
        doctor.is_active = not doctor.is_active
        doctor.user.is_active = doctor.is_active
        db.session.commit()
        
        status = 'activated' if doctor.is_active else 'deactivated'
        flash(f'Doctor {doctor.name} {status} successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating doctor status.', 'danger')
        app.logger.error(f'Doctor toggle error: {str(e)}')
    
    return redirect(url_for('doctors'))


@app.route('/patients')
@login_required
@receptionist_required
def patients():
    """List all patients"""
    search = request.args.get('search', '')
    
    query = Patient.query
    
    if search:
        query = query.filter(
            or_(
                Patient.name.ilike(f'%{search}%'),
                Patient.phone.ilike(f'%{search}%'),
                Patient.email.ilike(f'%{search}%')
            )
        )
    
    patients_list = query.order_by(Patient.created_at.desc()).all()
    
    return render_template('patients.html', patients=patients_list, search=search)


@app.route('/patients/new', methods=['GET', 'POST'])
@login_required
@receptionist_required
def patient_new():
    """Register new patient"""
    form = PatientForm()
    
    if form.validate_on_submit():
        try:
            patient = Patient(
                name=form.name.data,
                phone=form.phone.data,
                email=form.email.data,
                gender=form.gender.data,
                age=form.age.data,
                address=form.address.data,
                notes=form.notes.data
            )
            
            db.session.add(patient)
            db.session.commit()
            
            flash(f'Patient {patient.name} registered successfully!', 'success')
            return redirect(url_for('patients'))
        except Exception as e:
            db.session.rollback()
            flash('Error registering patient. Please try again.', 'danger')
            app.logger.error(f'Patient create error: {str(e)}')
    
    return render_template('patient_form.html', form=form, title='Register New Patient')


@app.route('/patients/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@receptionist_required
def patient_edit(id):
    """Edit patient information"""
    patient = Patient.query.get_or_404(id)
    form = PatientForm(obj=patient)
    
    if form.validate_on_submit():
        try:
            patient.name = form.name.data
            patient.phone = form.phone.data
            patient.email = form.email.data
            patient.gender = form.gender.data
            patient.age = form.age.data
            patient.address = form.address.data
            patient.notes = form.notes.data
            
            db.session.commit()
            
            flash(f'Patient {patient.name} updated successfully!', 'success')
            return redirect(url_for('patients'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating patient. Please try again.', 'danger')
            app.logger.error(f'Patient update error: {str(e)}')
    
    return render_template('patient_form.html', form=form, patient=patient, title='Edit Patient')


@app.route('/patients/<int:id>')
@login_required
def patient_view(id):
    """View patient details and history"""
    patient = Patient.query.get_or_404(id)
    
    appointments = Appointment.query.filter_by(patient_id=id).order_by(
        Appointment.appointment_datetime.desc()
    ).all()
    
    queue_history = QueueEntry.query.filter_by(patient_id=id).order_by(
        QueueEntry.created_at.desc()
    ).limit(20).all()
    
    prescriptions = Prescription.query.filter_by(patient_id=id).order_by(
        Prescription.created_at.desc()
    ).all()
    
    return render_template('patient_view.html',
                         patient=patient,
                         appointments=appointments,
                         queue_history=queue_history,
                         prescriptions=prescriptions)


@app.route('/queue')
@login_required
@receptionist_required
def queue():
    """Queue management page"""
    queue_date = request.args.get('date', date.today().isoformat())
    
    try:
        filter_date = datetime.strptime(queue_date, '%Y-%m-%d').date()
    except:
        filter_date = date.today()
    
    # Get queue entries for the date
    queue_entries = QueueEntry.query.filter_by(
        queue_date=filter_date
    ).order_by(QueueEntry.priority.desc(), QueueEntry.queue_number).all()
    
    # Get active doctors for assignment
    doctors_list = Doctor.query.filter_by(is_active=True).order_by(User.full_name).join(User).all()
    
    # Queue statistics
    stats = {
        'total': len(queue_entries),
        'waiting': len([q for q in queue_entries if q.status == 'Waiting']),
        'in_progress': len([q for q in queue_entries if q.status == 'With Doctor']),
        'completed': len([q for q in queue_entries if q.status == 'Completed']),
    }
    
    return render_template('queue.html',
                         queue_entries=queue_entries,
                         doctors=doctors_list,
                         stats=stats,
                         queue_date=filter_date)


@app.route('/queue/add', methods=['GET', 'POST'])
@login_required
@receptionist_required
def queue_add():
    """Add patient to queue"""
    form = QueueForm()
    
    # Populate choices
    form.patient_id.choices = [(0, 'New Walk-in Patient')] + [
        (p.id, f'{p.name} - {p.phone}') for p in Patient.query.order_by(Patient.name).all()
    ]
    form.doctor_id.choices = [(0, 'Unassigned')] + [
        (d.id, f'Dr. {d.user.full_name} - {d.specialization}') 
        for d in Doctor.query.filter_by(is_active=True).join(User).order_by(User.full_name).all()
    ]
    
    if form.validate_on_submit():
        try:
            doctor_id = form.doctor_id.data if form.doctor_id.data != 0 else None
            patient_id = form.patient_id.data if form.patient_id.data != 0 else None
            
            # Validate walk-in data if no patient selected
            if not patient_id:
                if not form.walk_in_name.data or not form.walk_in_phone.data:
                    flash('Please provide walk-in patient name and phone, or select an existing patient.', 'danger')
                    return render_template('queue_form.html', form=form)
            
            # Generate queue number
            queue_number = next_queue_number_for_today(doctor_id)
            
            queue_entry = QueueEntry(
                patient_id=patient_id,
                doctor_id=doctor_id,
                queue_number=queue_number,
                queue_date=date.today(),
                priority=form.priority.data,
                walk_in_name=form.walk_in_name.data if not patient_id else None,
                walk_in_phone=form.walk_in_phone.data if not patient_id else None,
                notes=form.notes.data,
                status='Waiting'
            )
            
            db.session.add(queue_entry)
            db.session.commit()
            
            patient_name = queue_entry.get_patient_name()
            flash(f'✓ {patient_name} added to queue with number #{queue_number}', 'success')
            return redirect(url_for('queue'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding to queue. Please try again.', 'danger')
            app.logger.error(f'Queue add error: {str(e)}')
    
    return render_template('queue_form.html', form=form)


@app.route('/queue/<int:id>/update-status', methods=['POST'])
@login_required
@receptionist_required
def queue_update_status(id):
    """Update queue entry status"""
    queue_entry = QueueEntry.query.get_or_404(id)
    new_status = request.form.get('status')
    
    if new_status not in ['Waiting', 'With Doctor', 'Completed', 'Canceled']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('queue'))
    
    try:
        old_status = queue_entry.status
        queue_entry.status = new_status
        
        # Track timing
        if new_status == 'With Doctor' and not queue_entry.started_at:
            queue_entry.started_at = datetime.utcnow()
        elif new_status == 'Completed' and not queue_entry.completed_at:
            queue_entry.completed_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Queue #{queue_entry.queue_number} status updated: {old_status} → {new_status}', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating queue status.', 'danger')
        app.logger.error(f'Queue update error: {str(e)}')
    
    return redirect(url_for('queue'))


@app.route('/queue/<int:id>/assign-doctor', methods=['POST'])
@login_required
@receptionist_required
def queue_assign_doctor(id):
    """Assign doctor to queue entry"""
    queue_entry = QueueEntry.query.get_or_404(id)
    doctor_id = request.form.get('doctor_id')
    
    if not doctor_id or doctor_id == '0':
        flash('Please select a doctor.', 'danger')
        return redirect(url_for('queue'))
    
    try:
        doctor = Doctor.query.get(int(doctor_id))
        if not doctor or not doctor.is_active:
            flash('Selected doctor is not available.', 'danger')
            return redirect(url_for('queue'))
        
        queue_entry.doctor_id = int(doctor_id)
        db.session.commit()
        
        flash(f'Queue #{queue_entry.queue_number} assigned to Dr. {doctor.name}', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error assigning doctor.', 'danger')
        app.logger.error(f'Queue assign doctor error: {str(e)}')
    
    return redirect(url_for('queue'))


@app.route('/queue/<int:id>/delete', methods=['POST'])
@login_required
@receptionist_required
def queue_delete(id):
    """Delete queue entry"""
    queue_entry = QueueEntry.query.get_or_404(id)
    
    try:
        queue_num = queue_entry.queue_number
        db.session.delete(queue_entry)
        db.session.commit()
        
        flash(f'Queue entry #{queue_num} removed.', 'info')
    except Exception as e:
        db.session.rollback()
        flash('Error removing queue entry.', 'danger')
        app.logger.error(f'Queue delete error: {str(e)}')
    
    return redirect(url_for('queue'))


@app.route('/queue/export')
@login_required
@receptionist_required
def queue_export():
    """Export queue data to CSV"""
    queue_date = request.args.get('date', date.today().isoformat())
    
    try:
        filter_date = datetime.strptime(queue_date, '%Y-%m-%d').date()
    except:
        filter_date = date.today()
    
    queue_entries = QueueEntry.query.filter_by(
        queue_date=filter_date
    ).order_by(QueueEntry.queue_number).all()
    
    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Queue #', 'Patient Name', 'Patient Phone', 'Doctor', 'Status', 'Priority', 'Created At', 'Notes'])
    
    for qe in queue_entries:
        doctor_name = f'Dr. {qe.doctor.name}' if qe.doctor else 'Unassigned'
        priority = 'Urgent' if qe.priority == 1 else 'Normal'
        
        writer.writerow([
            qe.queue_number,
            qe.get_patient_name(),
            qe.get_patient_phone(),
            doctor_name,
            qe.status,
            priority,
            qe.created_at.strftime('%Y-%m-%d %I:%M %p'),
            qe.notes or ''
        ])
    
    output = si.getvalue()
    si.close()
    
    response = make_response(output)
    response.headers['Content-Disposition'] = f'attachment; filename=queue_{filter_date}.csv'
    response.headers['Content-Type'] = 'text/csv'
    
    return response


# ============================================================================
# DOCTOR DASHBOARD ROUTES
# ============================================================================

@app.route('/doctor/dashboard')
@login_required
@doctor_required
def doctor_dashboard():
    """Doctor's personal dashboard"""
    # Get doctor's profile
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    if not doctor:
        flash('Doctor profile not found.', 'danger')
        return redirect(url_for('logout'))
    
    today = date.today()
    
    # Today's appointments
    today_appointments = Appointment.query.filter(
        Appointment.doctor_id == doctor.id,
        func.date(Appointment.appointment_datetime) == today
    ).order_by(Appointment.appointment_datetime).all()
    
    # Today's queue entries
    today_queue = QueueEntry.query.filter_by(
        doctor_id=doctor.id,
        queue_date=today
    ).order_by(QueueEntry.queue_number).all()
    
    # Statistics
    stats = {
        'appointments_today': len(today_appointments),
        'queue_waiting': len([q for q in today_queue if q.status == 'Waiting']),
        'queue_in_progress': len([q for q in today_queue if q.status == 'With Doctor']),
        'completed_today': len([q for q in today_queue if q.status == 'Completed']),
        'prescriptions_issued': Prescription.query.filter(
            Prescription.doctor_id == doctor.id,
            func.date(Prescription.created_at) == today
        ).count()
    }
    
    return render_template('doctor_dashboard.html',
                         doctor=doctor,
                         today_appointments=today_appointments,
                         today_queue=today_queue,
                         stats=stats)


@app.route('/doctor/queue/<int:id>/start', methods=['POST'])
@login_required
@doctor_required
def doctor_start_consultation(id):
    """Doctor starts consultation with queue patient"""
    queue_entry = QueueEntry.query.get_or_404(id)
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    if queue_entry.doctor_id != doctor.id:
        flash('You can only start consultations assigned to you.', 'danger')
        return redirect(url_for('doctor_dashboard'))
    
    try:
        queue_entry.status = 'With Doctor'
        queue_entry.started_at = datetime.utcnow()
        db.session.commit()
        
        flash(f'Started consultation with {queue_entry.get_patient_name()}', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error starting consultation.', 'danger')
        app.logger.error(f'Start consultation error: {str(e)}')
    
    return redirect(url_for('doctor_dashboard'))

@app.route('/doctor/appointment/<int:apt_id>/prescription', methods=['GET', 'POST'])
@login_required
@doctor_required
def doctor_issue_prescription_appointment(apt_id):
    """Issue prescription directly from appointment"""
    appointment = Appointment.query.get_or_404(apt_id)
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    # Verify appointment belongs to this doctor
    if appointment.doctor_id != doctor.id:
        flash('You can only issue prescriptions for your own appointments.', 'danger')
        return redirect(url_for('doctor_dashboard'))
    
    form = PrescriptionForm()
    
    if form.validate_on_submit():
        try:
            # Create prescription from appointment
            prescription = Prescription(
                patient_id=appointment.patient_id,  # Always has patient_id from appointment
                doctor_id=doctor.id,
                medication_details=form.medication_details.data,
                status='Issued'
            )
            db.session.add(prescription)
            db.session.commit()
            
            flash(f'✓ Prescription issued for {appointment.patient.name}', 'success')
            return redirect(url_for('doctor_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error issuing prescription.', 'danger')
            app.logger.error(f'Prescription error: {str(e)}')
    
    return render_template('doctor_issue_prescription_appointment.html',
                         form=form,
                         appointment=appointment,
                         doctor=doctor)


@app.route('/doctor/queue/<int:queue_id>/prescription', methods=['GET', 'POST'])
@login_required
@doctor_required
def doctor_issue_prescription_queue(queue_id):
    """Issue prescription directly from queue (after completion)"""
    queue_entry = QueueEntry.query.get_or_404(queue_id)
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    # Verify queue entry belongs to this doctor
    if queue_entry.doctor_id != doctor.id:
        flash('You can only issue prescriptions for your own queue entries.', 'danger')
        return redirect(url_for('doctor_dashboard'))
    
    form = PrescriptionForm()
    
    if form.validate_on_submit():
        try:
            # Create prescription from queue entry
            prescription = Prescription(
                patient_id=queue_entry.patient_id,
                doctor_id=doctor.id,
                queue_entry_id=queue_entry.id,
                medication_details=form.medication_details.data,
                status='Issued',
                walk_in_name=queue_entry.walk_in_name if not queue_entry.patient_id else None,
                walk_in_phone=queue_entry.walk_in_phone if not queue_entry.patient_id else None
            )
            db.session.add(prescription)
            db.session.commit()
            
            flash(f'✓ Prescription issued for {queue_entry.get_patient_name()}', 'success')
            return redirect(url_for('doctor_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error issuing prescription.', 'danger')
            app.logger.error(f'Prescription error: {str(e)}')
    
    return render_template('doctor_issue_prescription_queue.html',
                         form=form,
                         queue_entry=queue_entry,
                         doctor=doctor)

@app.route('/doctor/queue/<int:id>/complete', methods=['GET', 'POST'])
@login_required
@doctor_required
def doctor_complete_consultation(id):
    """Doctor completes consultation and issues prescription"""
    queue_entry = QueueEntry.query.get_or_404(id)
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    if queue_entry.doctor_id != doctor.id:
        flash('You can only complete consultations assigned to you.', 'danger')
        return redirect(url_for('doctor_dashboard'))
    
    form = PrescriptionForm()
    
    if form.validate_on_submit():
        try:
            # Create prescription - patient_id can now be NULL for walk-in patients
            prescription = Prescription(
                patient_id=queue_entry.patient_id,  # Can be None for walk-ins
                doctor_id=doctor.id,
                queue_entry_id=queue_entry.id,
                medication_details=form.medication_details.data,
                status='Issued',
                # Store walk-in details if no registered patient
                walk_in_name=queue_entry.walk_in_name if not queue_entry.patient_id else None,
                walk_in_phone=queue_entry.walk_in_phone if not queue_entry.patient_id else None
            )
            db.session.add(prescription)
            
            # Update queue status
            queue_entry.status = 'Completed'
            queue_entry.completed_at = datetime.utcnow()
            
            db.session.commit()
            
            patient_name = queue_entry.get_patient_name()
            flash(f'✓ Consultation completed and prescription issued for {patient_name}', 'success')
            return redirect(url_for('doctor_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error completing consultation.', 'danger')
            app.logger.error(f'Complete consultation error: {str(e)}')
    
    return render_template('doctor_complete_consultation.html', 
                         form=form, 
                         queue_entry=queue_entry,
                         doctor=doctor)

@app.route('/pharmacy')
@login_required
@pharmacist_required
def pharmacy():
    """Pharmacy dashboard - pending prescriptions"""
    status_filter = request.args.get('status', 'Issued')
    
    query = Prescription.query
    
    if status_filter:
        query = query.filter(Prescription.status == status_filter)
    
    prescriptions = query.order_by(Prescription.created_at.desc()).all()
    
    stats = {
        'pending': Prescription.query.filter_by(status='Issued').count(),
        'dispensed_today': Prescription.query.filter(
            Prescription.status == 'Dispensed',
            func.date(Prescription.dispensed_at) == date.today()
        ).count()
    }
    
    return render_template('pharmacy.html',
                         prescriptions=prescriptions,
                         stats=stats,
                         status_filter=status_filter)

@app.route('/pharmacy/history')
@login_required
@pharmacist_required
def pharmacy_prescription_history():
    """View all prescription history"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = Prescription.query
    
    # Search by patient name or phone
    if search:
        query = query.join(Patient, isouter=True).filter(
            or_(
                Patient.name.ilike(f'%{search}%'),
                Patient.phone.ilike(f'%{search}%'),
                Prescription.walk_in_name.ilike(f'%{search}%'),
                Prescription.walk_in_phone.ilike(f'%{search}%')
            )
        )
    
    # Filter by status
    if status_filter:
        query = query.filter(Prescription.status == status_filter)
    
    # Filter by date range
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
            query = query.filter(func.date(Prescription.created_at) >= from_date)
        except:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
            query = query.filter(func.date(Prescription.created_at) <= to_date)
        except:
            pass
    
    # Paginate results
    prescriptions = query.order_by(
        Prescription.created_at.desc()
    ).paginate(page=page, per_page=20)
    
    # Statistics
    stats = {
        'total_issued': Prescription.query.filter_by(status='Issued').count(),
        'total_dispensed': Prescription.query.filter_by(status='Dispensed').count(),
        'today_dispensed': Prescription.query.filter(
            Prescription.status == 'Dispensed',
            func.date(Prescription.dispensed_at) == date.today()
        ).count()
    }
    
    return render_template('pharmacy_prescription_history.html',
                         prescriptions=prescriptions,
                         stats=stats,
                         search=search,
                         status_filter=status_filter,
                         date_from=date_from,
                         date_to=date_to)

# ===== PHARMACY REPORTS =====
@app.route('/pharmacy/reports')
@login_required
@pharmacist_required
def pharmacy_reports():
    """Pharmacy analytics and reports"""
    date_from = request.args.get('date_from', (date.today() - timedelta(days=30)).isoformat())
    date_to = request.args.get('date_to', date.today().isoformat())
    
    try:
        from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
        to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
    except:
        from_date = date.today() - timedelta(days=30)
        to_date = date.today()
    
    # Query data for date range
    prescriptions = Prescription.query.filter(
        func.date(Prescription.created_at).between(from_date, to_date)
    ).all()
    
    # Statistics
    stats = {
        'total_prescriptions': len(prescriptions),
        'total_dispensed': len([p for p in prescriptions if p.status == 'Dispensed']),
        'pending': len([p for p in prescriptions if p.status == 'Issued']),
        'unique_patients': len(set([p.patient_id for p in prescriptions if p.patient_id])),
        'unique_doctors': len(set([p.doctor_id for p in prescriptions])),
        'dispensing_rate': (len([p for p in prescriptions if p.status == 'Dispensed']) / len(prescriptions) * 100) if prescriptions else 0
    }
    
    # Top doctors
    doctor_stats = {}
    for rx in prescriptions:
        doctor_id = rx.doctor_id
        if doctor_id not in doctor_stats:
            doctor_stats[doctor_id] = {'count': 0, 'dispensed': 0}
        doctor_stats[doctor_id]['count'] += 1
        if rx.status == 'Dispensed':
            doctor_stats[doctor_id]['dispensed'] += 1
    
    top_doctors = sorted(
        [(Doctor.query.get(did), counts['count'], counts['dispensed']) 
         for did, counts in doctor_stats.items()],
        key=lambda x: x[1],
        reverse=True
    )[:5]
    
    # Daily distribution
    daily_data = {}
    for rx in prescriptions:
        day = rx.created_at.date()
        if day not in daily_data:
            daily_data[day] = {'issued': 0, 'dispensed': 0}
        daily_data[day]['issued'] += 1
        if rx.status == 'Dispensed':
            daily_data[day]['dispensed'] += 1
    
    return render_template('pharmacy_reports.html',
                         stats=stats,
                         top_doctors=top_doctors,
                         daily_data=daily_data,
                         date_from=date_from,
                         date_to=date_to)


# ===== PHARMACY INVENTORY =====
@app.route('/pharmacy/inventory')
@login_required
@pharmacist_required
def pharmacy_inventory():
    """View and manage medicine inventory"""
    inventory = MedicineStock.query.all()
    low_stock = [item for item in inventory if item.is_low_stock()]
    expiring_soon = [item for item in inventory if item.days_to_expiry() and item.days_to_expiry() <= 30 and item.days_to_expiry() > 0]
    expired = [item for item in inventory if item.is_expired()]
    
    return render_template('pharmacy_inventory.html',
                         inventory=inventory,
                         low_stock=low_stock,
                         expiring_soon=expiring_soon,
                         expired=expired)


@app.route('/pharmacy/inventory/add', methods=['GET', 'POST'])
@login_required
@pharmacist_required
def add_medicine():
    """Add new medicine to inventory"""
    if request.method == 'POST':
        try:
            medicine = MedicineStock(
                medicine_name=request.form.get('medicine_name'),
                current_stock=int(request.form.get('current_stock', 0)),
                min_stock_level=int(request.form.get('min_stock_level', 10)),
                unit_price=float(request.form.get('unit_price', 0)),
                expiry_date=datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date() if request.form.get('expiry_date') else None
            )
            db.session.add(medicine)
            db.session.commit()
            flash(f'✓ {medicine.medicine_name} added to inventory', 'success')
            return redirect(url_for('pharmacy_inventory'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding medicine', 'danger')
            app.logger.error(f'Add medicine error: {str(e)}')
    
    return render_template('add_medicine.html')


@app.route('/pharmacy/inventory/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@pharmacist_required
def edit_medicine(id):
    """Edit medicine stock"""
    medicine = MedicineStock.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            medicine.medicine_name = request.form.get('medicine_name')
            medicine.current_stock = int(request.form.get('current_stock', 0))
            medicine.min_stock_level = int(request.form.get('min_stock_level', 10))
            medicine.unit_price = float(request.form.get('unit_price', 0))
            medicine.expiry_date = datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date() if request.form.get('expiry_date') else None
            medicine.last_updated = datetime.utcnow()
            
            db.session.commit()
            flash(f'✓ {medicine.medicine_name} updated', 'success')
            return redirect(url_for('pharmacy_inventory'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating medicine', 'danger')
            app.logger.error(f'Edit medicine error: {str(e)}')
    
    return render_template('edit_medicine.html', medicine=medicine)


# ===== PRESCRIPTION PRINT/EXPORT =====
@app.route('/pharmacy/prescription/<int:id>/print')
@login_required
@pharmacist_required
def print_prescription(id):
    """Print prescription in patient-friendly format"""
    prescription = Prescription.query.get_or_404(id)
    return render_template('prescription_print.html', prescription=prescription)


@app.route('/pharmacy/prescription/<int:id>/validate', methods=['POST'])
@login_required
@pharmacist_required
def validate_prescription(id):
    """Validate prescription before dispensing"""
    prescription = Prescription.query.get_or_404(id)
    
    validation_issues = []
    
    # Check if patient info is complete
    if not prescription.patient_id and not prescription.walk_in_name:
        validation_issues.append('Patient information missing')
    
    # Check if medication details are complete
    if not prescription.medication_details:
        validation_issues.append('Medication details missing')
    
    # Check if prescription is old (>30 days)
    days_old = (datetime.utcnow() - prescription.created_at).days
    if days_old > 30:
        validation_issues.append(f'Prescription is {days_old} days old - May need verification')
    
    return jsonify({
        'valid': len(validation_issues) == 0,
        'issues': validation_issues
    })

@app.route('/pharmacy/prescription/<int:id>/dispense', methods=['POST'])
@login_required
@pharmacist_required
def pharmacy_dispense(id):
    """Mark prescription as dispensed"""
    prescription = Prescription.query.get_or_404(id)
    
    if prescription.status == 'Dispensed':
        flash('This prescription has already been dispensed.', 'warning')
        return redirect(url_for('pharmacy'))
    
    try:
        prescription.status = 'Dispensed'
        prescription.dispensed_at = datetime.utcnow()
        prescription.dispensed_by = current_user.id
        
        db.session.commit()
        
        flash(f'Prescription dispensed for {prescription.patient.name}', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error dispensing prescription.', 'danger')
        app.logger.error(f'Dispense error: {str(e)}')
    
    return redirect(url_for('pharmacy'))


@app.route('/pharmacy/prescription/<int:id>')
@login_required
@pharmacist_required
def pharmacy_prescription_view(id):
    """View prescription details"""
    prescription = Prescription.query.get_or_404(id)
    
    return render_template('pharmacy_prescription_view.html',
                         prescription=prescription)


# ============================================================================
# PHARMACIST MANAGEMENT ROUTES (Admin only)
# ============================================================================

@app.route('/pharmacists')
@login_required
@admin_required
def pharmacists():
    """List all pharmacists"""
    pharmacists_list = User.query.filter_by(role='pharmacist').order_by(User.full_name).all()
    
    return render_template('pharmacists.html', pharmacists=pharmacists_list)


@app.route('/pharmacists/new', methods=['GET', 'POST'])
@login_required
@admin_required
def pharmacist_new():
    """Create new pharmacist account"""
    form = PharmacistForm()
    
    if form.validate_on_submit():
        try:
            # Check if emp_no or email already exists
            existing_user = User.query.filter(
                or_(User.emp_no == form.emp_no.data, User.email == form.email.data)
            ).first()
            
            if existing_user:
                flash('Employee No. or Email already exists.', 'danger')
                return render_template('pharmacist_form.html', form=form, title='Add New Pharmacist')
            
            # Create pharmacist account
            new_pharmacist = User(
                emp_no=form.emp_no.data,
                email=form.email.data,
                full_name=form.full_name.data,
                role='pharmacist'
            )
            new_pharmacist.set_password(form.password.data)
            
            db.session.add(new_pharmacist)
            db.session.commit()
            
            flash(f'Pharmacist {new_pharmacist.full_name} created successfully!', 'success')
            return redirect(url_for('pharmacists'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating pharmacist account. Please try again.', 'danger')
            app.logger.error(f'Pharmacist create error: {str(e)}')
    
    return render_template('pharmacist_form.html', form=form, title='Add New Pharmacist')


@app.route('/pharmacists/<int:id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def pharmacist_toggle_active(id):
    """Toggle pharmacist active status"""
    pharmacist = User.query.get_or_404(id)
    
    if pharmacist.role != 'pharmacist':
        flash('Invalid user type.', 'danger')
        return redirect(url_for('pharmacists'))
    
    try:
        pharmacist.is_active = not pharmacist.is_active
        db.session.commit()
        
        status = 'activated' if pharmacist.is_active else 'deactivated'
        flash(f'Pharmacist {pharmacist.full_name} {status} successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating pharmacist status.', 'danger')
        app.logger.error(f'Pharmacist toggle error: {str(e)}')
    
    return redirect(url_for('pharmacists'))

# ============================================================================
# APPOINTMENTS ROUTES
# ============================================================================

@app.route('/appointments')
@login_required
@receptionist_required
def appointments():
    """List all appointments with filters"""
    status_filter = request.args.get('status', '')
    date_filter = request.args.get('date', '')
    doctor_filter = request.args.get('doctor', '')
    
    query = Appointment.query
    
    if status_filter:
        query = query.filter(Appointment.status == status_filter)
    
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(func.date(Appointment.appointment_datetime) == filter_date)
        except:
            pass
    
    if doctor_filter:
        query = query.filter(Appointment.doctor_id == int(doctor_filter))
    
    appointments_list = query.order_by(Appointment.appointment_datetime.desc()).all()
    
    # Get doctors for filter
    doctors_list = Doctor.query.filter_by(is_active=True).join(User).order_by(User.full_name).all()
    
    return render_template('appointments.html',
                         appointments=appointments_list,
                         doctors=doctors_list,
                         status_filter=status_filter,
                         date_filter=date_filter,
                         doctor_filter=doctor_filter)


class AppointmentForm(FlaskForm):
    """Appointment booking form"""
    patient_id = SelectField('Patient', coerce=int, validators=[DataRequired()])
    doctor_id = SelectField('Doctor', coerce=int, validators=[DataRequired()])
    appointment_datetime = StringField('Date & Time', validators=[DataRequired()])
    notes = TextAreaField('Notes', validators=[Optional()])


def validate_appointment_slot(doctor_id, appointment_datetime, exclude_appointment_id=None):
    """Validate if appointment slot is available"""
    doctor = Doctor.query.get(doctor_id)
    if not doctor or not doctor.is_active:
        return False, "Doctor not available"
    
    time_buffer = timedelta(minutes=30)
    start_time = appointment_datetime - time_buffer
    end_time = appointment_datetime + time_buffer
    
    query = Appointment.query.filter(
        Appointment.doctor_id == doctor_id,
        Appointment.appointment_datetime.between(start_time, end_time),
        Appointment.status.in_(['Booked'])
    )
    
    if exclude_appointment_id:
        query = query.filter(Appointment.id != exclude_appointment_id)
    
    if query.first():
        return False, "This time slot is not available. Please choose another time."
    
    return True, None


@app.route('/appointments/new', methods=['GET', 'POST'])
@login_required
@receptionist_required
def appointment_new():
    """Book new appointment"""
    form = AppointmentForm()
    
    # Populate choices
    form.patient_id.choices = [(0, 'Select Patient')] + [
        (p.id, f'{p.name} - {p.phone}') for p in Patient.query.order_by(Patient.name).all()
    ]
    form.doctor_id.choices = [(0, 'Select Doctor')] + [
        (d.id, f'Dr. {d.name} - {d.specialization}') 
        for d in Doctor.query.filter_by(is_active=True).join(User).order_by(User.full_name).all()
    ]
    
    if form.validate_on_submit():
        try:
            # Parse datetime
            appointment_datetime = datetime.strptime(
                form.appointment_datetime.data, 
                '%Y-%m-%dT%H:%M'
            )
            
            # Validate slot
            is_valid, error_msg = validate_appointment_slot(
                form.doctor_id.data, 
                appointment_datetime
            )
            
            if not is_valid:
                flash(error_msg, 'danger')
                return render_template('appointment_form.html', form=form, title='Book Appointment')
            
            appointment = Appointment(
                patient_id=form.patient_id.data,
                doctor_id=form.doctor_id.data,
                appointment_datetime=appointment_datetime,
                notes=form.notes.data,
                created_by=current_user.id,
                status='Booked'
            )
            
            db.session.add(appointment)
            db.session.commit()
            
            patient = Patient.query.get(form.patient_id.data)
            doctor = Doctor.query.get(form.doctor_id.data)
            
            flash(f'Appointment booked for {patient.name} with Dr. {doctor.name} on {appointment_datetime.strftime("%b %d, %Y at %I:%M %p")}', 'success')
            return redirect(url_for('appointments'))
        except ValueError:
            flash('Invalid date/time format. Please use the date picker.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash('Error booking appointment. Please try again.', 'danger')
            app.logger.error(f'Appointment create error: {str(e)}')
    
    return render_template('appointment_form.html', form=form, title='Book Appointment')


@app.route('/appointments/<int:id>/reschedule', methods=['GET', 'POST'])
@login_required
@receptionist_required
def appointment_reschedule(id):
    """Reschedule appointment"""
    appointment = Appointment.query.get_or_404(id)
    
    if appointment.status == 'Completed':
        flash('Cannot reschedule a completed appointment.', 'warning')
        return redirect(url_for('appointments'))
    
    if request.method == 'POST':
        try:
            new_datetime_str = request.form.get('new_datetime')
            new_datetime = datetime.strptime(new_datetime_str, '%Y-%m-%dT%H:%M')
            
            # Validate new slot
            is_valid, error_msg = validate_appointment_slot(
                appointment.doctor_id,
                new_datetime,
                exclude_appointment_id=id
            )
            
            if not is_valid:
                flash(error_msg, 'danger')
                return redirect(url_for('appointments'))
            
            old_time = appointment.appointment_datetime
            appointment.appointment_datetime = new_datetime
            appointment.status = 'Booked'
            
            db.session.commit()
            
            flash(f'Appointment rescheduled from {old_time.strftime("%b %d at %I:%M %p")} to {new_datetime.strftime("%b %d at %I:%M %p")}', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error rescheduling appointment.', 'danger')
            app.logger.error(f'Appointment reschedule error: {str(e)}')
        
        return redirect(url_for('appointments'))
    
    return render_template('appointment_reschedule.html', appointment=appointment)


@app.route('/appointments/<int:id>/cancel', methods=['POST'])
@login_required
@receptionist_required
def appointment_cancel(id):
    """Cancel appointment"""
    appointment = Appointment.query.get_or_404(id)
    
    if appointment.status == 'Completed':
        flash('Cannot cancel a completed appointment.', 'warning')
        return redirect(url_for('appointments'))
    
    try:
        appointment.status = 'Canceled'
        db.session.commit()
        
        flash(f'Appointment canceled for {appointment.patient.name} with Dr. {appointment.doctor.name}', 'info')
    except Exception as e:
        db.session.rollback()
        flash('Error canceling appointment.', 'danger')
        app.logger.error(f'Appointment cancel error: {str(e)}')
    
    return redirect(url_for('appointments'))


@app.route('/appointments/<int:id>/complete', methods=['POST'])
@login_required
@receptionist_required
def appointment_complete(id):
    """Mark appointment as completed"""
    appointment = Appointment.query.get_or_404(id)
    
    try:
        appointment.status = 'Completed'
        db.session.commit()
        
        flash(f'Appointment marked as completed.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating appointment.', 'danger')
        app.logger.error(f'Appointment complete error: {str(e)}')
    
    return redirect(url_for('appointments'))


@app.route('/appointments/<int:id>/no-show', methods=['POST'])
@login_required
@receptionist_required
def appointment_no_show(id):
    """Mark appointment as no-show"""
    appointment = Appointment.query.get_or_404(id)
    
    try:
        appointment.status = 'No-Show'
        db.session.commit()
        
        flash(f'Appointment marked as no-show.', 'warning')
    except Exception as e:
        db.session.rollback()
        flash('Error updating appointment.', 'danger')
        app.logger.error(f'Appointment no-show error: {str(e)}')
    
    return redirect(url_for('appointments'))


@app.route('/appointments/export')
@login_required
@receptionist_required
def appointments_export():
    """Export appointments to CSV"""
    date_filter = request.args.get('date', date.today().isoformat())
    
    try:
        filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
    except:
        filter_date = date.today()
    
    appointments_list = Appointment.query.filter(
        func.date(Appointment.appointment_datetime) == filter_date
    ).order_by(Appointment.appointment_datetime).all()
    
    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'Patient Name', 'Patient Phone', 'Doctor', 'Date & Time', 'Status', 'Notes'])
    
    for apt in appointments_list:
        writer.writerow([
            apt.id,
            apt.patient.name,
            apt.patient.phone,
            f'Dr. {apt.doctor.name}',
            apt.appointment_datetime.strftime('%Y-%m-%d %I:%M %p'),
            apt.status,
            apt.notes or ''
        ])
    
    output = si.getvalue()
    si.close()
    
    response = make_response(output)
    response.headers['Content-Disposition'] = f'attachment; filename=appointments_{filter_date}.csv'
    response.headers['Content-Type'] = 'text/csv'
    
    return response


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/patients/search')
@login_required
def api_patients_search():
    """Search patients by name or phone (for autocomplete)"""
    query = request.args.get('q', '')
    
    if len(query) < 2:
        return jsonify([])
    
    patients = Patient.query.filter(
        or_(
            Patient.name.ilike(f'%{query}%'),
            Patient.phone.ilike(f'%{query}%')
        )
    ).limit(10).all()
    
    results = [{
        'id': p.id,
        'name': p.name,
        'phone': p.phone,
        'email': p.email or ''
    } for p in patients]
    
    return jsonify(results)


@app.route('/api/doctors/<int:id>/slots')
@login_required
def api_doctor_slots(id):
    """Get available slots for a doctor on a specific date"""
    doctor = Doctor.query.get_or_404(id)
    date_str = request.args.get('date')
    
    if not date_str:
        return jsonify({'error': 'Date required'}), 400
    
    try:
        check_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except:
        return jsonify({'error': 'Invalid date format'}), 400
    
    # Get existing appointments for that day
    existing_appointments = Appointment.query.filter(
        Appointment.doctor_id == id,
        func.date(Appointment.appointment_datetime) == check_date,
        Appointment.status == 'Booked'
    ).all()
    
    booked_times = [apt.appointment_datetime.strftime('%H:%M') for apt in existing_appointments]
    
    return jsonify({
        'doctor_name': doctor.name,
        'availability': doctor.availability,
        'booked_slots': booked_times
    })


@app.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    """Get real-time dashboard statistics"""
    stats = get_dashboard_stats()
    return jsonify(stats)


# ============================================================================
# TEMPLATE FILTERS
# ============================================================================

@app.template_filter('datetime_format')
def datetime_format(value, format='%b %d, %Y at %I:%M %p'):
    """Format datetime for display"""
    if value is None:
        return ''
    return value.strftime(format)


@app.template_filter('date_format')
def date_format(value, format='%b %d, %Y'):
    """Format date for display"""
    if value is None:
        return ''
    if isinstance(value, datetime):
        return value.strftime(format)
    return value.strftime(format)


@app.template_filter('time_ago')
def time_ago(value):
    """Convert datetime to 'time ago' format"""
    if value is None:
        return ''
    
    now = datetime.utcnow()
    if isinstance(value, date) and not isinstance(value, datetime):
        value = datetime.combine(value, datetime.min.time())
    
    diff = now - value
    
    if diff.days > 365:
        return f'{diff.days // 365} year(s) ago'
    elif diff.days > 30:
        return f'{diff.days // 30} month(s) ago'
    elif diff.days > 0:
        return f'{diff.days} day(s) ago'
    elif diff.seconds > 3600:
        return f'{diff.seconds // 3600} hour(s) ago'
    elif diff.seconds > 60:
        return f'{diff.seconds // 60} minute(s) ago'
    else:
        return 'just now'


@app.template_filter('status_badge')
def status_badge(status):
    """Return Bootstrap badge class for status"""
    status_classes = {
        'Booked': 'primary',
        'Completed': 'success',
        'Canceled': 'secondary',
        'No-Show': 'warning',
        'Waiting': 'info',
        'With Doctor': 'warning',
        'Issued': 'info',
        'Dispensed': 'success'
    }
    return status_classes.get(status, 'secondary')


# ============================================================================
# DATABASE INITIALIZATION AND SEEDING
# ============================================================================

def init_database():
    """Initialize database with tables"""
    with app.app_context():
        db.create_all()
        print("✓ Database tables created successfully")


def seed_data():
    """Seed database with initial data"""
    with app.app_context():
        # Check if data already exists
        if User.query.first():
            print("⚠ Database already contains data. Skipping seed.")
            return
        
        print("Seeding database with initial data...")
        
        # Create admin user
        admin = User(
            emp_no='admin',
            email='admin@clinic.com',
            full_name='Admin User',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Create receptionist
        receptionist = User(
            emp_no='rec001',
            email='receptionist@clinic.com',
            full_name='Receptionist Staff',
            role='receptionist'
        )
        receptionist.set_password('rec123')
        db.session.add(receptionist)
        
        # Create pharmacist
        pharmacist = User(
            emp_no='pharm001',
            email='pharmacist@clinic.com',
            full_name='Pharmacy Staff',
            role='pharmacist'
        )
        pharmacist.set_password('pharm123')
        db.session.add(pharmacist)
        db.session.flush()
        
        # Create sample doctors with user accounts
        doctors_data = [
            {
                'emp_no': 'doc001',
                'email': 'dr.sarah@clinic.com',
                'full_name': 'Dr. Sarah Johnson',
                'password': 'doc123',
                'specialization': 'General Physician',
                'gender': 'Female',
                'location': 'Building A, Room 101',
                'phone': '9876543210',
                'consultation_fee': 500,
                'availability': 'Mon-Fri 09:00-17:00'
            },
            {
                'emp_no': 'doc002',
                'email': 'dr.rajesh@clinic.com',
                'full_name': 'Dr. Rajesh Kumar',
                'password': 'doc123',
                'specialization': 'Cardiologist',
                'gender': 'Male',
                'location': 'Building B, Room 205',
                'phone': '9876543211',
                'consultation_fee': 1000,
                'availability': 'Mon, Wed, Fri 10:00-16:00'
            },
            {
                'emp_no': 'doc003',
                'email': 'dr.priya@clinic.com',
                'full_name': 'Dr. Priya Sharma',
                'password': 'doc123',
                'specialization': 'Pediatrician',
                'gender': 'Female',
                'location': 'Building A, Room 103',
                'phone': '9876543212',
                'consultation_fee': 700,
                'availability': 'Tue-Sat 08:00-14:00'
            },
            {
                'emp_no': 'doc004',
                'email': 'dr.michael@clinic.com',
                'full_name': 'Dr. Michael Chen',
                'password': 'doc123',
                'specialization': 'Orthopedic',
                'gender': 'Male',
                'location': 'Building C, Room 301',
                'phone': '9876543213',
                'consultation_fee': 1200,
                'availability': 'Mon-Thu 11:00-18:00'
            }
        ]
        
        for doc_data in doctors_data:
            # Create user account
            user = User(
                emp_no=doc_data['emp_no'],
                email=doc_data['email'],
                full_name=doc_data['full_name'],
                role='doctor'
            )
            user.set_password(doc_data['password'])
            db.session.add(user)
            db.session.flush()
            
            # Create doctor profile
            doctor = Doctor(
                user_id=user.id,
                specialization=doc_data['specialization'],
                gender=doc_data['gender'],
                location=doc_data['location'],
                phone=doc_data['phone'],
                consultation_fee=doc_data['consultation_fee'],
                availability=doc_data['availability']
            )
            db.session.add(doctor)
        
        # Create sample patients
        patients_data = [
            {
                'name': 'Amit Patel',
                'phone': '9123456780',
                'email': 'amit@example.com',
                'gender': 'Male',
                'age': 35,
                'address': '123 Main Street, Mysuru'
            },
            {
                'name': 'Sita Reddy',
                'phone': '9123456781',
                'email': 'sita@example.com',
                'gender': 'Female',
                'age': 28,
                'address': '456 Park Avenue, Mysuru'
            },
            {
                'name': 'Rohan Singh',
                'phone': '9123456782',
                'gender': 'Male',
                'age': 42
            },
            {
                'name': 'Lakshmi Nair',
                'phone': '9123456783',
                'email': 'lakshmi@example.com',
                'gender': 'Female',
                'age': 55,
                'address': '789 Temple Road, Mysuru'
            }
        ]
        
        for pat_data in patients_data:
            patient = Patient(**pat_data)
            db.session.add(patient)
        
        db.session.commit()
        
        print("✓ Database seeded successfully!")
        print("\n" + "="*60)
        print("DEFAULT LOGIN CREDENTIALS:")
        print("="*60)
        print("\nAdmin:")
        print("  Employee No: admin")
        print("  Password: admin123")
        print("\nReceptionist:")
        print("  Employee No: rec001")
        print("  Password: rec123")
        print("\nDoctor (any):")
        print("  Employee No: doc001, doc002, doc003, doc004")
        print("  Password: doc123")
        print("\nPharmacist:")
        print("  Employee No: pharm001")
        print("  Password: pharm123")
        print("="*60 + "\n")


# ============================================================================
# CLI COMMANDS
# ============================================================================

@app.cli.command()
def init_db():
    """Initialize the database."""
    init_database()


@app.cli.command()
def seed_db():
    """Seed the database with sample data."""
    seed_data()


@app.cli.command()
def reset_db():
    """Reset the database (drop all tables and recreate)."""
    if input("⚠ This will delete all data. Continue? (yes/no): ").lower() == 'yes':
        db.drop_all()
        print("✓ All tables dropped")
        init_database()
        seed_data()


@app.cli.command()
def create_admin():
    """Create a new admin user interactively."""
    print("\n=== Create New Admin User ===\n")
    
    emp_no = input("Employee No: ")
    email = input("Email: ")
    full_name = input("Full Name: ")
    password = input("Password: ")
    
    # Check if user exists
    existing = User.query.filter(
        or_(User.emp_no == emp_no, User.email == email)
    ).first()
    
    if existing:
        print("❌ Employee No or Email already exists!")
        return
    
    admin = User(
        emp_no=emp_no,
        email=email,
        full_name=full_name,
        role='admin'
    )
    admin.set_password(password)
    
    db.session.add(admin)
    db.session.commit()
    
    print(f"\n✓ Admin user '{full_name}' created successfully!")
    print(f"  Login with: {emp_no} / {password}\n")


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Seed if empty
        if not User.query.first():
            print("\n" + "="*60)
            print("FIRST TIME SETUP - Creating initial data...")
            print("="*60 + "\n")
            seed_data()
    
    # Run the application
    print("\n" + "="*60)
    print("🏥 CLINIC MANAGEMENT SYSTEM")
    print("="*60)
    print("Server starting...")
    print("Access the application at: http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)