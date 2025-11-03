# 🏥 Clinic Management System

A comprehensive web-based clinic management system built with Flask, designed to streamline healthcare operations from patient registration to prescription dispensing.

## 🌐 Live Demo

**Access the live application:** [clinic.pythonanywhere.com](https://clinic.pythonanywhere.com)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [User Roles & Workflows](#user-roles--workflows)
- [Installation](#installation)
- [Default Login Credentials](#default-login-credentials)
- [Complete Workflow Guide](#complete-workflow-guide)
- [Technology Stack](#technology-stack)
- [Database Schema](#database-schema)
- [API Endpoints](#api-endpoints)
- [Screenshots](#screenshots)

---

## 🎯 Overview

The Clinic Management System is designed to digitize and optimize the complete healthcare delivery process in clinics and hospitals. It manages four key user roles with distinct responsibilities and provides seamless workflows from patient arrival to medication dispensing.

### Key Capabilities

- **Patient Management** - Registration, records, and history tracking
- **Appointment Scheduling** - Book, reschedule, and manage appointments
- **Queue Management** - Walk-in patient queue with real-time status updates
- **Doctor Dashboard** - Consultation management and prescription issuance
- **Pharmacy System** - Prescription tracking, inventory, and dispensing
- **Multi-Role Access** - Admin, Receptionist, Doctor, and Pharmacist interfaces
- **Analytics & Reports** - Dashboard statistics and exportable reports

---

## ✨ Features

### 🔐 Authentication & Authorization
- Secure login system with role-based access control
- Password hashing using Werkzeug security
- Session management with Flask-Login
- Change password functionality for all users

### 👥 Patient Management
- Register new patients with complete details
- Search patients by name, phone, or email
- View patient history (appointments, consultations, prescriptions)
- Edit patient information
- Track all interactions with the clinic

### 📅 Appointment System
- Book appointments with specific doctors
- Date/time picker for scheduling
- Automatic slot validation (prevents double-booking)
- Reschedule or cancel appointments
- View appointments by date, doctor, or status
- Export appointments to CSV

### 🚶 Walk-in Queue Management
- Add walk-in patients to queue (registered or anonymous)
- Auto-generate queue numbers
- Assign patients to specific doctors
- Priority marking for urgent cases
- Real-time queue status tracking:
  - **Waiting** - Patient in queue
  - **With Doctor** - Consultation in progress
  - **Completed** - Consultation finished
  - **Canceled** - Removed from queue
- Queue export functionality

### 👨‍⚕️ Doctor Interface
- Personal dashboard with daily overview
- View assigned appointments and queue
- Start consultations with queue patients
- Issue prescriptions after consultation
- Track consultation timing (start/complete)
- View prescription history

### 💊 Pharmacy Module
- View pending prescriptions (issued by doctors)
- Validate prescription details
- Dispense medications and mark as complete
- Prescription history with search and filters
- Print prescriptions for patients
- Analytics dashboard:
  - Daily dispensing statistics
  - Top prescribing doctors
  - Dispensing rate trends

### 📦 Inventory Management (Pharmacy)
- Add medicines to inventory
- Track stock levels with alerts
- Set minimum stock thresholds
- Monitor expiry dates
- Low stock and expiring medicine alerts
- Price management

### 📊 Analytics & Reporting
- Dashboard with real-time statistics
- Today's appointments and queue count
- Completed consultations tracking
- Pending prescriptions count
- Doctor performance metrics
- Export functionality (CSV format)

### 👑 Admin Controls
- Create and manage doctor accounts
- Create and manage pharmacist accounts
- Activate/deactivate user accounts
- View all system activities
- Complete system oversight

---

## 👤 User Roles & Workflows

### 1️⃣ **Admin**
**Responsibilities:**
- System configuration and user management
- Create doctor and pharmacist accounts
- Activate/deactivate users
- Monitor overall system performance

**Key Actions:**
- Add new doctors with specializations
- Create pharmacist accounts
- Toggle user active status
- Access all system reports

---

### 2️⃣ **Receptionist**
**Responsibilities:**
- Front desk operations
- Patient registration and check-in
- Appointment scheduling
- Queue management

**Typical Workflow:**

#### Patient Arrival:
1. **Registered Patient:**
   - Search existing patient by name/phone
   - Book appointment OR add to walk-in queue
   - Assign to appropriate doctor based on specialization

2. **New Patient:**
   - Register patient with full details
   - Either schedule appointment or add to walk-in queue
   - Collect basic medical history

#### Appointment Management:
- View daily appointment schedule
- Reschedule or cancel as needed
- Mark appointments as completed/no-show
- Export appointment lists

#### Queue Management:
- Monitor real-time queue status
- Assign walk-ins to available doctors
- Update queue status as patients progress
- Handle priority cases

---

### 3️⃣ **Doctor**
**Responsibilities:**
- Patient consultations
- Medical assessment
- Prescription issuance

**Typical Workflow:**

#### Daily Routine:
1. **Login to Dashboard:**
   - View today's appointments
   - Check assigned queue patients
   - Review statistics

2. **Handle Appointments:**
   - See scheduled appointment details
   - Issue prescription if needed
   - Mark consultation as complete

3. **Process Queue Patients:**
   - View waiting patients assigned to you
   - Click "Start Consultation" when ready
   - Patient status changes to "With Doctor"
   - Conduct consultation
   - Click "Complete Consultation"
   - Fill in prescription details
   - Submit prescription

4. **Prescription Creation:**
   - Enter medication details, dosage, duration
   - Add any special instructions
   - Prescription automatically sent to pharmacy
   - Queue status updated to "Completed"

---

### 4️⃣ **Pharmacist**
**Responsibilities:**
- Medication dispensing
- Prescription validation
- Inventory management

**Typical Workflow:**

#### Prescription Processing:
1. **View Pending Prescriptions:**
   - Dashboard shows all "Issued" prescriptions
   - See doctor name, patient details, medications

2. **Validate Prescription:**
   - Review prescription details
   - Check medication availability in inventory
   - Verify patient information

3. **Dispense Medication:**
   - Prepare medicines as prescribed
   - Update inventory stock levels
   - Click "Dispense" button
   - Print prescription receipt for patient
   - Prescription marked as "Dispensed"

#### Inventory Management:
- Monitor low stock alerts
- Track expiring medicines
- Add new stock
- Update prices
- Generate inventory reports

---

## 🔄 Complete System Workflow

### Scenario 1: Scheduled Appointment Patient

```
1. Patient calls clinic
   ↓
2. Receptionist searches/registers patient
   ↓
3. Receptionist books appointment with specific doctor
   ↓
4. Patient arrives on appointment day
   ↓
5. Doctor sees appointment in dashboard
   ↓
6. Doctor conducts consultation
   ↓
7. Doctor issues prescription (if needed)
   ↓
8. Prescription appears in Pharmacy dashboard
   ↓
9. Pharmacist validates and dispenses medication
   ↓
10. Patient receives medicines and receipt
```

### Scenario 2: Walk-in Patient

```
1. Patient walks into clinic
   ↓
2. Receptionist adds patient to queue
   - If registered: Select existing patient
   - If new: Enter walk-in details (name, phone)
   ↓
3. Receptionist assigns to available doctor
   ↓
4. Patient gets queue number (e.g., #5)
   ↓
5. Doctor sees patient in queue on dashboard
   ↓
6. When ready, doctor clicks "Start Consultation"
   - Queue status: "Waiting" → "With Doctor"
   ↓
7. Doctor conducts consultation
   ↓
8. Doctor clicks "Complete & Issue Prescription"
   ↓
9. Doctor fills prescription form and submits
   - Queue status: "With Doctor" → "Completed"
   - Prescription created with status "Issued"
   ↓
10. Prescription automatically appears in Pharmacy
   ↓
11. Pharmacist sees prescription in pending list
   ↓
12. Pharmacist prepares medicines
   ↓
13. Pharmacist clicks "Dispense"
   - Status: "Issued" → "Dispensed"
   - Timestamp recorded
   ↓
14. Pharmacist prints receipt
   ↓
15. Patient receives medicines
```

### Scenario 3: Emergency/Priority Patient

```
1. Urgent patient arrives
   ↓
2. Receptionist adds to queue with "Priority: Urgent"
   ↓
3. Priority patients appear at top of queue
   ↓
4. Doctor processes priority patient immediately
   ↓
5. [Follows standard consultation workflow]
```

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd clinic-management-system
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
```
Flask==2.3.0
Flask-SQLAlchemy==3.0.5
Flask-Login==0.6.2
Flask-WTF==1.1.1
WTForms==3.0.1
Werkzeug==2.3.0
```

### Step 4: Initialize Database

```bash
# Create database tables
python app.py
```

The application will automatically:
- Create all database tables
- Seed initial data if database is empty
- Display default login credentials

### Step 5: Run Application

```bash
python app.py
```

Application will be available at: `http://localhost:5000`

---

## 🔑 Default Login Credentials

The system comes pre-configured with test accounts:

### Admin Account
```
Employee No: admin
Password: admin123
```

### Receptionist Account
```
Employee No: rec001
Password: rec123
```

### Doctor Accounts
```
Employee No: doc001, doc002, doc003, doc004
Password: doc123
```
- Dr. Sarah Johnson (General Physician)
- Dr. Rajesh Kumar (Cardiologist)
- Dr. Priya Sharma (Pediatrician)
- Dr. Michael Chen (Orthopedic)

### Pharmacist Account
```
Employee No: pharm001
Password: pharm123
```

**⚠️ Important:** Change these default passwords in production!

---

## 🛠️ Database Commands

### Initialize Database
```bash
flask init-db
```

### Seed Sample Data
```bash
flask seed-db
```

### Reset Database (⚠️ Deletes all data)
```bash
flask reset-db
```

### Create New Admin User
```bash
flask create-admin
```

---

## 💻 Technology Stack

### Backend
- **Flask** - Python web framework
- **SQLAlchemy** - ORM for database operations
- **Flask-Login** - User session management
- **Flask-WTF** - Form handling and validation
- **Werkzeug** - Password hashing and security

### Frontend
- **HTML5/CSS3** - Structure and styling
- **Bootstrap 5** - Responsive UI framework
- **JavaScript** - Dynamic interactions
- **Jinja2** - Template engine

### Database
- **SQLite** - Development database (default)
- **PostgreSQL/MySQL** - Production ready (configurable)

### Security Features
- Password hashing (PBKDF2)
- CSRF protection
- Session security
- Role-based access control
- SQL injection prevention (ORM)

---

## 📊 Database Schema

### Core Tables

#### Users Table
```python
- id (Primary Key)
- emp_no (Unique) - Employee number
- email (Unique)
- password_hash
- full_name
- role (admin/receptionist/doctor/pharmacist)
- is_active
- created_at
```

#### Patients Table
```python
- id (Primary Key)
- name
- phone
- email
- gender
- age
- address
- notes
- created_at
```

#### Doctors Table
```python
- id (Primary Key)
- user_id (Foreign Key → Users)
- specialization
- gender
- location
- phone
- availability
- consultation_fee
- is_active
- created_at
```

#### Appointments Table
```python
- id (Primary Key)
- patient_id (Foreign Key → Patients)
- doctor_id (Foreign Key → Doctors)
- appointment_datetime
- status (Booked/Completed/Canceled/No-Show)
- notes
- created_by (Foreign Key → Users)
- created_at
- updated_at
```

#### Queue Entries Table
```python
- id (Primary Key)
- patient_id (Foreign Key → Patients, nullable)
- doctor_id (Foreign Key → Doctors, nullable)
- queue_number
- queue_date
- status (Waiting/With Doctor/Completed/Canceled)
- priority (0=Normal, 1=Urgent)
- notes
- walk_in_name (for anonymous patients)
- walk_in_phone (for anonymous patients)
- created_at
- started_at
- completed_at
```

#### Prescriptions Table
```python
- id (Primary Key)
- patient_id (Foreign Key → Patients, nullable)
- doctor_id (Foreign Key → Doctors)
- queue_entry_id (Foreign Key → Queue Entries, nullable)
- medication_details (Text)
- status (Issued/Dispensed)
- walk_in_name (for anonymous patients)
- walk_in_phone (for anonymous patients)
- created_at
- dispensed_at
- dispensed_by (Foreign Key → Users)
```

#### Medicine Stock Table
```python
- id (Primary Key)
- medicine_name (Unique)
- current_stock
- min_stock_level
- unit_price
- expiry_date
- last_updated
```

---

## 🔌 API Endpoints

### Authentication
```
POST   /login                    - User login
GET    /logout                   - User logout
POST   /change-password          - Change password
```

### Dashboard
```
GET    /dashboard                - Role-based dashboard redirect
```

### Patients
```
GET    /patients                 - List all patients
GET    /patients/new             - Patient registration form
POST   /patients/new             - Create new patient
GET    /patients/<id>/edit       - Edit patient form
POST   /patients/<id>/edit       - Update patient
GET    /patients/<id>            - View patient details
```

### Doctors (Admin)
```
GET    /doctors                  - List all doctors
GET    /doctors/new              - Add doctor form
POST   /doctors/new              - Create doctor account
GET    /doctors/<id>/edit        - Edit doctor form
POST   /doctors/<id>/edit        - Update doctor
POST   /doctors/<id>/toggle-active - Activate/deactivate
```

### Appointments
```
GET    /appointments             - List appointments
GET    /appointments/new         - Book appointment form
POST   /appointments/new         - Create appointment
GET    /appointments/<id>/reschedule - Reschedule form
POST   /appointments/<id>/reschedule - Update appointment time
POST   /appointments/<id>/cancel - Cancel appointment
POST   /appointments/<id>/complete - Mark as completed
POST   /appointments/<id>/no-show - Mark as no-show
GET    /appointments/export      - Export to CSV
```

### Queue Management
```
GET    /queue                    - View queue
GET    /queue/add                - Add to queue form
POST   /queue/add                - Create queue entry
POST   /queue/<id>/update-status - Update queue status
POST   /queue/<id>/assign-doctor - Assign doctor
POST   /queue/<id>/delete        - Remove from queue
GET    /queue/export             - Export to CSV
```

### Doctor Dashboard
```
GET    /doctor/dashboard         - Doctor's dashboard
POST   /doctor/queue/<id>/start  - Start consultation
GET    /doctor/queue/<id>/complete - Complete consultation form
POST   /doctor/queue/<id>/complete - Issue prescription
GET    /doctor/appointment/<id>/prescription - Issue prescription from appointment
POST   /doctor/appointment/<id>/prescription - Create prescription
```

### Pharmacy
```
GET    /pharmacy                 - Pharmacy dashboard
GET    /pharmacy/history         - Prescription history
GET    /pharmacy/reports         - Analytics reports
POST   /pharmacy/prescription/<id>/dispense - Dispense medication
GET    /pharmacy/prescription/<id> - View prescription details
GET    /pharmacy/prescription/<id>/print - Print prescription
GET    /pharmacy/inventory       - View inventory
GET    /pharmacy/inventory/add   - Add medicine form
POST   /pharmacy/inventory/add   - Create medicine entry
GET    /pharmacy/inventory/<id>/edit - Edit medicine form
POST   /pharmacy/inventory/<id>/edit - Update medicine
```

### Pharmacists (Admin)
```
GET    /pharmacists              - List pharmacists
GET    /pharmacists/new          - Add pharmacist form
POST   /pharmacists/new          - Create pharmacist account
POST   /pharmacists/<id>/toggle-active - Activate/deactivate
```

### AJAX/API Routes
```
GET    /api/patients/search      - Search patients (autocomplete)
GET    /api/doctors/<id>/slots   - Get available doctor slots
GET    /api/dashboard/stats      - Real-time dashboard stats
POST   /pharmacy/prescription/<id>/validate - Validate prescription
```

---


## 🔒 Security Considerations

### Production Deployment Checklist

1. **Change Secret Key:**
```python
# Use a strong, random secret key
app.config['SECRET_KEY'] = 'your-production-secret-key-here'
```

2. **Change All Default Passwords**

3. **Use Production Database:**
```python
# PostgreSQL example
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@localhost/clinic_db'
```

4. **Enable HTTPS**

5. **Set Debug Mode to False:**
```python
app.run(debug=False)
```

6. **Configure CORS if needed**

7. **Implement Rate Limiting**

8. **Regular Backups**

9. **Monitor Error Logs**

10. **Keep Dependencies Updated**

---

## 🐛 Troubleshooting

### Database Issues
```bash
# If database gets corrupted
flask reset-db

# If migration issues occur
rm app.db
python app.py
```

### Login Problems
```bash
# Reset admin password
flask create-admin
```

### Port Already in Use
```python
# Change port in app.py
app.run(debug=True, host='0.0.0.0', port=5001)
```

---

## 📝 Future Enhancements

- [ ] SMS/Email notifications for appointments
- [ ] Patient mobile app
- [ ] Doctor mobile app
- [ ] Video consultation integration
- [ ] Lab test management
- [ ] Billing and invoicing
- [ ] Insurance integration
- [ ] Multi-clinic support
- [ ] Advanced analytics dashboard
- [ ] Automated appointment reminders
- [ ] Prescription templates
- [ ] Medical history timeline
- [ ] Document upload (reports, scans)
---

## 🌐 Live Application

**Access the deployed application:**

🔗 **[clinic.pythonanywhere.com](https://clinic.pythonanywhere.com)**

Use the default credentials provided above to explore the system!

