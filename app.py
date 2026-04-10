"""
Hospital Management System v3.0
Python Flask + SQLite
Complete End-to-End with:
  - Pharmacy: Medicine stock + Dispense to Patients + Purchase/Stock-In
  - Staff/User Management: Create users with roles + module access control
  - All modules fully functional end-to-end
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, g, abort
import sqlite3, os, hashlib, json
from datetime import datetime, date, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'evren_hms_v3_2025'
DATABASE = os.path.join(os.path.dirname(__file__), 'hms.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def qdb(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def edb(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid

def hash_pw(pw): return hashlib.md5(pw.encode()).hexdigest()

# ─────────────────────────────────────────────
# AUTH & PERMISSIONS
# ─────────────────────────────────────────────
ALL_MODULES = [
    'dashboard','patients','opd','ipd','beds','lab','pharmacy',
    'staff','payroll','hr_leave','hr_attendance','hr_appraisal','hr_training',
    'appointments','bloodbank','insurance','vehicle',
    'income','expenses','reports','admin'
]

def get_user(): return session.get('hospitaladmin', {})

def get_user_permissions():
    user = get_user()
    if not user: return {}
    if user.get('roles') == 'Super Admin':
        return {m: {'view':True,'add':True,'edit':True,'delete':True} for m in ALL_MODULES}
    role_id = user.get('role_id', 0)
    rows = qdb("SELECT module,can_view,can_add,can_edit,can_delete FROM role_permissions WHERE role_id=?", (role_id,))
    return {r['module']: {'view':bool(r['can_view']),'add':bool(r['can_add']),'edit':bool(r['can_edit']),'delete':bool(r['can_delete'])} for r in rows}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'hospitaladmin' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def perm_required(module, action='view'):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'hospitaladmin' not in session:
                return redirect(url_for('login'))
            user = get_user()
            if user.get('roles') == 'Super Admin':
                return f(*args, **kwargs)
            perms = get_user_permissions()
            if not perms.get(module, {}).get(action):
                flash(f'Access denied: {action} permission required for {module}.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def audit(action, module, record_id=0, details=''):
    try:
        user = get_user()
        edb("INSERT INTO audit_log (user_id,user_name,action,module,record_id,details,ip_address) VALUES (?,?,?,?,?,?,?)",
            (user.get('id',0), user.get('username',''), action, module, record_id, details, request.remote_addr))
    except: pass

@app.context_processor
def inject_globals():
    user = get_user()
    perms = get_user_permissions() if user else {}
    settings = {}
    if user:
        try:
            rows = qdb("SELECT name,value FROM sch_settings")
            settings = {r['name']: r['value'] for r in rows}
        except: pass
    return dict(current_user=type('U', (), user)() if user else None,
                user_perms=perms, settings=settings,
                ALL_MODULES=ALL_MODULES)

# ─────────────────────────────────────────────
# SCHEMA
# ─────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS sch_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, value TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '', is_active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, role_id INTEGER NOT NULL,
    module TEXT NOT NULL, can_view INTEGER DEFAULT 0, can_add INTEGER DEFAULT 0,
    can_edit INTEGER DEFAULT 0, can_delete INTEGER DEFAULT 0,
    UNIQUE(role_id, module), FOREIGN KEY (role_id) REFERENCES roles(id)
);
CREATE TABLE IF NOT EXISTS department (
    id INTEGER PRIMARY KEY AUTOINCREMENT, department_name TEXT NOT NULL,
    description TEXT DEFAULT '', is_active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS staff_designation (
    id INTEGER PRIMARY KEY AUTOINCREMENT, designation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT UNIQUE,
    name TEXT NOT NULL, surname TEXT DEFAULT '', email TEXT UNIQUE,
    password TEXT DEFAULT '', phone TEXT DEFAULT '', mobileno TEXT DEFAULT '',
    gender TEXT DEFAULT '', dob TEXT DEFAULT '', blood_group TEXT DEFAULT '',
    date_of_joining TEXT DEFAULT '', address TEXT DEFAULT '',
    department INTEGER DEFAULT 0, designation INTEGER DEFAULT 0,
    qualification TEXT DEFAULT '', experience TEXT DEFAULT '',
    basic_salary REAL DEFAULT 0, bank_name TEXT DEFAULT '',
    bank_account TEXT DEFAULT '', emergency_contact TEXT DEFAULT '',
    note TEXT DEFAULT '', is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (department) REFERENCES department(id)
);
CREATE TABLE IF NOT EXISTS staff_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER UNIQUE,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (staff_id) REFERENCES staff(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_unique_id TEXT UNIQUE,
    patient_name TEXT NOT NULL, guardian_name TEXT DEFAULT '',
    gender TEXT DEFAULT '', dob TEXT DEFAULT '', age INTEGER DEFAULT 0,
    blood_group TEXT DEFAULT '', mobile TEXT DEFAULT '',
    email TEXT DEFAULT '', address TEXT DEFAULT '',
    patient_type TEXT DEFAULT 'OPD', notes TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER DEFAULT 0, doctor_id INTEGER DEFAULT 0,
    appointment_date TEXT DEFAULT '', appointment_time TEXT DEFAULT '',
    department_id INTEGER DEFAULT 0, type TEXT DEFAULT 'OPD',
    status TEXT DEFAULT 'scheduled', priority TEXT DEFAULT 'normal',
    symptoms TEXT DEFAULT '', note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS opd_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL, doctor_id INTEGER DEFAULT 0,
    date TEXT DEFAULT CURRENT_DATE, symptoms TEXT DEFAULT '',
    diagnosis TEXT DEFAULT '', charge REAL DEFAULT 0,
    payment_status TEXT DEFAULT 'unpaid', tpa_id INTEGER DEFAULT 0,
    follow_up_date TEXT DEFAULT '', note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
CREATE TABLE IF NOT EXISTS ipd_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL, doctor_id INTEGER DEFAULT 0,
    bed INTEGER DEFAULT 0, date TEXT DEFAULT CURRENT_DATE,
    discharge_date TEXT DEFAULT '', discharged TEXT DEFAULT 'no',
    charge REAL DEFAULT 0, payment_status TEXT DEFAULT 'unpaid',
    tpa_id INTEGER DEFAULT 0, note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
CREATE TABLE IF NOT EXISTS bed_type (
    id INTEGER PRIMARY KEY AUTOINCREMENT, bed_type TEXT NOT NULL, charge_per_day REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS floor (
    id INTEGER PRIMARY KEY AUTOINCREMENT, floor_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bed_group (
    id INTEGER PRIMARY KEY AUTOINCREMENT, bed_group TEXT NOT NULL,
    floor_id INTEGER DEFAULT 0, description TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS bed (
    id INTEGER PRIMARY KEY AUTOINCREMENT, bed_name TEXT NOT NULL,
    bed_type_id INTEGER DEFAULT 0, bed_group_id INTEGER DEFAULT 0,
    is_active TEXT DEFAULT 'yes'
);
CREATE TABLE IF NOT EXISTS medicine_category (
    id INTEGER PRIMARY KEY AUTOINCREMENT, medicine_category TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pharmacy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    medicine_name TEXT NOT NULL, medicine_company TEXT DEFAULT '',
    medicine_composition TEXT DEFAULT '', medicine_category_id INTEGER DEFAULT 0,
    medicine_group TEXT DEFAULT '', unit TEXT DEFAULT 'Tablet',
    reorder_level INTEGER DEFAULT 10
);
CREATE TABLE IF NOT EXISTS medicine_batch_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT, pharmacy_id INTEGER NOT NULL,
    batch_no TEXT DEFAULT '', manufacture_date TEXT DEFAULT '',
    expiry_date TEXT DEFAULT '', purchase_price REAL DEFAULT 0,
    sale_price REAL DEFAULT 0, available_quantity INTEGER DEFAULT 0,
    FOREIGN KEY (pharmacy_id) REFERENCES pharmacy(id)
);
-- NEW: Medicine dispensing to patients
CREATE TABLE IF NOT EXISTS medicine_dispense (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER DEFAULT NULL, pharmacy_id INTEGER NOT NULL,
    batch_id INTEGER DEFAULT 0, quantity INTEGER DEFAULT 1,
    sale_price REAL DEFAULT 0, total_amount REAL DEFAULT 0,
    dispense_date TEXT DEFAULT CURRENT_DATE,
    dispensed_by INTEGER DEFAULT 0, opd_id INTEGER DEFAULT 0,
    ipd_id INTEGER DEFAULT 0, note TEXT DEFAULT '',
    payment_status TEXT DEFAULT 'paid',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pharmacy_id) REFERENCES pharmacy(id)
);
-- NEW: Stock purchase / stock-in
CREATE TABLE IF NOT EXISTS medicine_purchase (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pharmacy_id INTEGER NOT NULL, supplier_name TEXT DEFAULT '',
    invoice_no TEXT DEFAULT '', purchase_date TEXT DEFAULT CURRENT_DATE,
    batch_no TEXT DEFAULT '', manufacture_date TEXT DEFAULT '',
    expiry_date TEXT DEFAULT '', purchase_price REAL DEFAULT 0,
    sale_price REAL DEFAULT 0, quantity INTEGER DEFAULT 0,
    total_cost REAL DEFAULT 0, note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pharmacy_id) REFERENCES pharmacy(id)
);
CREATE TABLE IF NOT EXISTS expense_head (
    id INTEGER PRIMARY KEY AUTOINCREMENT, exp_category TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    exp_head_id INTEGER DEFAULT 0, invoice_no TEXT DEFAULT '',
    amount REAL DEFAULT 0, date TEXT DEFAULT CURRENT_DATE, note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS income_head (
    id INTEGER PRIMARY KEY AUTOINCREMENT, income_category TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS income (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    income_head_id INTEGER DEFAULT 0, invoice_no TEXT DEFAULT '',
    amount REAL DEFAULT 0, date TEXT DEFAULT CURRENT_DATE, note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS payroll (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER NOT NULL,
    month TEXT DEFAULT '', year INTEGER DEFAULT 0,
    basic_salary REAL DEFAULT 0, allowances REAL DEFAULT 0,
    deductions REAL DEFAULT 0, net_salary REAL DEFAULT 0,
    payment_status TEXT DEFAULT 'unpaid', payment_date TEXT DEFAULT '',
    note TEXT DEFAULT '',
    FOREIGN KEY (staff_id) REFERENCES staff(id)
);
CREATE TABLE IF NOT EXISTS lab_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
    test_name TEXT NOT NULL, doctor_id INTEGER DEFAULT 0,
    test_date TEXT DEFAULT CURRENT_DATE, result TEXT DEFAULT '',
    normal_range TEXT DEFAULT '', unit TEXT DEFAULT '',
    status TEXT DEFAULT 'pending', note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
CREATE TABLE IF NOT EXISTS userlog (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER DEFAULT 0,
    action TEXT DEFAULT 'login', ip_address TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS visitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_name TEXT NOT NULL,
    patient_id INTEGER DEFAULT 0, purpose TEXT DEFAULT '',
    visit_date TEXT DEFAULT CURRENT_DATE, visit_time TEXT DEFAULT '',
    note TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tpa (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organisation_name TEXT NOT NULL, contact_person TEXT DEFAULT '',
    email TEXT DEFAULT '', phone TEXT DEFAULT '', address TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1, coverage_limit REAL DEFAULT 0,
    policy_details TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS vehicle (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_name TEXT NOT NULL, vehicle_number TEXT DEFAULT '',
    vehicle_type TEXT DEFAULT 'ambulance', driver_name TEXT DEFAULT '',
    driver_phone TEXT DEFAULT '', status TEXT DEFAULT 'available',
    last_maintenance TEXT DEFAULT '', fuel_type TEXT DEFAULT 'Diesel'
);
CREATE TABLE IF NOT EXISTS vehicle_trips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id INTEGER NOT NULL, patient_id INTEGER DEFAULT 0,
    trip_date TEXT DEFAULT CURRENT_DATE, pickup_location TEXT DEFAULT '',
    drop_location TEXT DEFAULT '', distance_km REAL DEFAULT 0,
    charge REAL DEFAULT 0, driver_id INTEGER DEFAULT 0,
    status TEXT DEFAULT 'completed', note TEXT DEFAULT '',
    FOREIGN KEY (vehicle_id) REFERENCES vehicle(id)
);
CREATE TABLE IF NOT EXISTS leave_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    days_allowed INTEGER DEFAULT 0, carry_forward INTEGER DEFAULT 0,
    description TEXT DEFAULT '', is_active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS leave_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER NOT NULL,
    leave_type_id INTEGER NOT NULL, from_date TEXT NOT NULL,
    to_date TEXT NOT NULL, total_days INTEGER DEFAULT 1,
    reason TEXT DEFAULT '', status TEXT DEFAULT 'pending',
    approved_by INTEGER DEFAULT 0, approved_date TEXT DEFAULT '',
    note TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (staff_id) REFERENCES staff(id)
);
CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER NOT NULL,
    date TEXT NOT NULL, time_in TEXT DEFAULT '', time_out TEXT DEFAULT '',
    status TEXT DEFAULT 'present', note TEXT DEFAULT '',
    FOREIGN KEY (staff_id) REFERENCES staff(id), UNIQUE(staff_id, date)
);
CREATE TABLE IF NOT EXISTS performance_appraisal (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER NOT NULL,
    period TEXT NOT NULL, reviewer_id INTEGER DEFAULT 0,
    punctuality INTEGER DEFAULT 0, teamwork INTEGER DEFAULT 0,
    technical_skills INTEGER DEFAULT 0, communication INTEGER DEFAULT 0,
    patient_care INTEGER DEFAULT 0, overall_score REAL DEFAULT 0,
    grade TEXT DEFAULT '', strengths TEXT DEFAULT '', improvements TEXT DEFAULT '',
    goals TEXT DEFAULT '', reviewer_comments TEXT DEFAULT '',
    status TEXT DEFAULT 'draft', review_date TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (staff_id) REFERENCES staff(id)
);
CREATE TABLE IF NOT EXISTS training (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
    category TEXT DEFAULT '', trainer TEXT DEFAULT '',
    start_date TEXT DEFAULT '', end_date TEXT DEFAULT '',
    duration_hours INTEGER DEFAULT 0, location TEXT DEFAULT '',
    description TEXT DEFAULT '', is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS training_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT, training_id INTEGER NOT NULL,
    staff_id INTEGER NOT NULL, status TEXT DEFAULT 'enrolled',
    score INTEGER DEFAULT 0, certificate_issued INTEGER DEFAULT 0,
    completion_date TEXT DEFAULT '',
    FOREIGN KEY (training_id) REFERENCES training(id),
    FOREIGN KEY (staff_id) REFERENCES staff(id),
    UNIQUE(training_id, staff_id)
);
CREATE TABLE IF NOT EXISTS blood_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT, blood_group TEXT NOT NULL UNIQUE,
    units_available INTEGER DEFAULT 0, last_updated TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS blood_donations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, donor_name TEXT NOT NULL,
    blood_group TEXT NOT NULL, donor_contact TEXT DEFAULT '',
    donor_age INTEGER DEFAULT 0, donation_date TEXT DEFAULT CURRENT_DATE,
    units_donated INTEGER DEFAULT 1, status TEXT DEFAULT 'available',
    expiry_date TEXT DEFAULT '', note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS blood_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER DEFAULT 0,
    blood_group TEXT NOT NULL, units_required INTEGER DEFAULT 1,
    request_date TEXT DEFAULT CURRENT_DATE, required_date TEXT DEFAULT '',
    doctor_id INTEGER DEFAULT 0, status TEXT DEFAULT 'pending',
    purpose TEXT DEFAULT '', note TEXT DEFAULT '',
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER DEFAULT 0,
    user_name TEXT DEFAULT '', action TEXT DEFAULT '',
    module TEXT DEFAULT '', record_id INTEGER DEFAULT 0,
    details TEXT DEFAULT '', ip_address TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


# ─────────────────────────────────────────────
# SEED DATA
# ─────────────────────────────────────────────
def seed_data(db):
    # Check if already seeded
    existing = db.execute("SELECT COUNT(*) as c FROM staff").fetchone()['c']
    if existing > 0:
        return

    today = date.today().isoformat()

    # Settings
    settings = [
        ('name','EVREN Hospital'),('email','admin@hospital.com'),
        ('phone','+1-555-000-0000'),('address','123 Medical Drive, Healthcare City'),
        ('currency','INR'),('currency_symbol','₹'),('timezone','UTC'),
        ('date_format','d-m-Y'),('time_format','12'),('theme','default')
    ]
    for k,v in settings:
        db.execute("INSERT OR IGNORE INTO sch_settings (name,value) VALUES (?,?)", (k,v))

    # Roles
    roles = [
        ('Super Admin','Full system access'),('Admin','System administration'),
        ('Doctor','Clinical access'),('Nurse','Ward and patient care'),
        ('Pharmacist','Pharmacy management'),('Receptionist','Front desk operations'),
        ('Accountant','Finance and billing'),('HR Manager','Human resources'),
        ('Lab Technician','Laboratory operations'),
    ]
    for name,desc in roles:
        db.execute("INSERT OR IGNORE INTO roles (name,description) VALUES (?,?)", (name,desc))
    db.commit()

    # Role permissions
    role_map = {r['name']:r['id'] for r in db.execute("SELECT id,name FROM roles").fetchall()}
    admin_skip = set()  # modules admin can't touch
    super_admin_id = role_map.get('Super Admin',1)

    module_perms = {
        'Admin':     {m:(1,1,1,1) for m in ALL_MODULES if m!='admin'},
        'Doctor':    {m:(1,0,0,0) for m in ['dashboard','patients','opd','ipd','beds','lab','appointments','bloodbank']},
        'Nurse':     {m:(1,0,0,0) for m in ['dashboard','patients','opd','ipd','beds','lab']},
        'Pharmacist':{m:(1,1,1,0) for m in ['dashboard','patients','pharmacy']},
        'Receptionist':{m:(1,1,0,0) for m in ['dashboard','patients','appointments','opd','visitors']},
        'Accountant':{m:(1,1,1,0) for m in ['dashboard','income','expenses','reports','payroll','insurance']},
        'HR Manager':{m:(1,1,1,0) for m in ['dashboard','staff','payroll','hr_leave','hr_attendance','hr_appraisal','hr_training']},
        'Lab Technician':{m:(1,1,1,0) for m in ['dashboard','patients','lab']},
    }
    for role_name, mods in module_perms.items():
        rid = role_map.get(role_name)
        if not rid: continue
        for mod,(v,a,e,d) in mods.items():
            db.execute("INSERT OR IGNORE INTO role_permissions (role_id,module,can_view,can_add,can_edit,can_delete) VALUES (?,?,?,?,?,?)",
                       (rid,mod,v,a,e,d))
    db.commit()

    # Departments
    depts = ['Cardiology','Orthopedics','Neurology','Pediatrics','General Medicine',
             'Emergency','Gynecology','Oncology','Radiology','Psychiatry','Dermatology','ENT','Pharmacy','Administration']
    for d in depts:
        db.execute("INSERT OR IGNORE INTO department (department_name) VALUES (?)", (d,))
    db.commit()
    dept_map = {r['department_name']:r['id'] for r in db.execute("SELECT id,department_name FROM department").fetchall()}

    # Designations
    desigs = ['Senior Consultant','Junior Doctor','Resident Doctor','Head Nurse','Staff Nurse',
              'Chief Pharmacist','Pharmacist','Lab Head','Lab Technician','Admin Officer','HR Manager','Accountant']
    for d in desigs:
        db.execute("INSERT OR IGNORE INTO staff_designation (designation) VALUES (?)", (d,))
    db.commit()
    desig_map = {r['designation']:r['id'] for r in db.execute("SELECT id,designation FROM staff_designation").fetchall()}

    # Staff users
    staff_list = [
        ('EMP001','Admin','User','admin@hospital.com','admin123','+1-555-0001','Super Admin','Administration','Admin Officer',50000),
        ('EMP002','Dr. John','Smith','doctor@hospital.com','admin123','+1-555-0002','Doctor','General Medicine','Senior Consultant',80000),
        ('EMP003','Mary','Johnson','nurse@hospital.com','admin123','+1-555-0003','Nurse','General Medicine','Head Nurse',40000),
        ('EMP004','David','Lee','pharmacist@hospital.com','admin123','+1-555-0004','Pharmacist','Pharmacy','Chief Pharmacist',45000),
        ('EMP005','Sara','Wilson','reception@hospital.com','admin123','+1-555-0005','Receptionist','Administration','Admin Officer',35000),
        ('EMP006','Tom','Davis','accounts@hospital.com','admin123','+1-555-0006','Accountant','Administration','Accountant',42000),
        ('EMP007','Linda','Brown','hr@hospital.com','admin123','+1-555-0007','HR Manager','Administration','HR Manager',43000),
        ('EMP008','Dr. Emily','Chen','doctor2@hospital.com','admin123','+1-555-0008','Doctor','Cardiology','Senior Consultant',85000),
    ]
    for emp_id,name,surname,email,pw,phone,role_name,dept_name,desig_name,salary in staff_list:
        dept_id = dept_map.get(dept_name,1)
        desig_id = desig_map.get(desig_name,1)
        sid = db.execute("INSERT OR IGNORE INTO staff (employee_id,name,surname,email,password,phone,mobileno,gender,date_of_joining,department,designation,basic_salary,blood_group) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (emp_id,name,surname,email,hash_pw(pw),phone,phone,'Male' if name.startswith('Dr. J') or name in ['David','Tom'] else 'Female',
             today,dept_id,desig_id,salary,'O+')).lastrowid
        role_id = role_map.get(role_name,1)
        db.execute("INSERT OR IGNORE INTO staff_roles (staff_id,role_id) VALUES (?,?)", (sid,role_id))
    db.commit()

    # Medicine categories
    cats = ['Tablet','Capsule','Syrup','Injection','Cream/Ointment','Eye Drops','Ear Drops','Inhaler','Powder','Suspension','General','Surgical']
    for c in cats:
        db.execute("INSERT OR IGNORE INTO medicine_category (medicine_category) VALUES (?)", (c,))
    db.commit()
    cat_map = {r['medicine_category']:r['id'] for r in db.execute("SELECT id,medicine_category FROM medicine_category").fetchall()}

    # Medicines with stock - loaded from VIDHATHRI MEDICAL STORES stock data
    medicines = [
        ('1 INCH PLASTER', '', '', 'Tablet', 'PAPER PLASTER', 20.0, 67.5, 10),
        ('25D', '', '', 'Tablet', 'GENERAL', 17.0, 21.4, 7),
        ('5D 500 I.V FLUID', '', '', 'Tablet', 'GENERAL', 35.12, 92.14, 5),
        ('ACCUSURE LIFE GLUCOSE METER', '', '', 'Tablet', 'GLUCOSE MACHINE', 1.0, 999.0, 1),
        ('ACCUSURE LIFE GLUCOSE STRIPS', '', '', 'Tablet', 'GLUCO STRIPS', 13.2, 23.0, 50),
        ('ACTIVWELL SYP', '', '', 'Syrup', 'SYRUP', 128.14, 172.91, 22),
        ('ADHESIVE PLASTER 10CM', '', '', 'Tablet', 'GENERAL', 120.0, 200.0, 1),
        ('ADNEON 2ML', '', '', 'Injection', 'INJECTION', 155.0, 207.95, 10),
        ('ADULT DIAPERS (L)', '', '', 'Tablet', 'GENERAL', 25.98, 60.0, 5),
        ('ADVENT 1.2GM INJ', '', '', 'Injection', 'INJECTION', 67.8, 150.24, 26),
        ('AERO NEB MASK (A)', '', '', 'Tablet', 'SURGICAL', 56.72, 415.64, 11),
        ('AMLOKIND AT TAB', '', '', 'Tablet', 'TABLET', 3.11, 4.08, 90),
        ('ANGIWELL 2.6', '', '', 'Tablet', 'TABLET', 180.82, 246.52, 6),
        ('ANO METROGYL CREM 20GM', '', '', 'Cream/Ointment', 'GEL', 104.84, 146.77, 3),
        ('ANOBLISS-CREAM', '', '', 'Cream/Ointment', 'CREAM/OINT/GEL', 106.9, 149.66, 2),
        ('ARVAST 10MG TAB', '', '', 'Tablet', 'TABLET', 10.67, 16.2, 15),
        ('ARVAST GOLD 10MG TAB', '', '', 'Tablet', 'TABLET', 12.79, 16.78, 110),
        ('ATARAX 25MG TAB', '', '', 'Tablet', 'TABLET', 5.41, 7.09, 91),
        ('ATCHOL 40', '', '', 'Tablet', 'TABLET', 7.82, 10.26, 140),
        ('ATOSMET 500', '', '', 'Tablet', 'TABLET', 1.42, 1.86, 60),
        ('ATOSNERVE-D', '', '', 'Tablet', 'TABLET', 12.5, 16.41, 100),
        ('AVIL 25MG TABS', '', '', 'Tablet', 'TABLET', 0.52, 0.73, 280),
        ('AVIL 2ML', '', '', 'Injection', 'INJECTION', 4.93, 6.26, 11),
        ('AVIL 2ML INJ', '', '', 'Injection', 'INJECTION', 4.7, 6.26, 33),
        ('AZEE 500MG TAB', '', '', 'Tablet', 'TABLET', 19.18, 25.18, 65),
        ('BANDAGE 4INCH', '', '', 'Tablet', 'GENERAL', 15.0, 40.0, 3),
        ('BANDAGE 6INCH', '', '', 'Tablet', 'GENERAL', 11.41, 42.23, 39),
        ('BD 10ML SYRINGE', '', '', 'Tablet', 'SYRINGE', 9.29, 11.3, 129),
        ('BD MINI PEN NEEDLE', '', '', 'Tablet', 'NEEDLE', 14.56, 85.36, 47),
        ('BEPLEX FORT TAB', '', '', 'Tablet', 'TABLET', 1.85, 2.66, 235),
        ('BETADINE 100', '', '', 'Cream/Ointment', 'LOTION', 82.32, 102.9, 2),
        ('BETAVERT 16 MG TAB', '', '', 'Tablet', 'TABLET', 14.62, 19.19, 104),
        ('BETT 0.5ML', '', '', 'Injection', 'AMPLE', 10.65, 13.31, 20),
        ('BILAMONT TAB', '', '', 'Tablet', 'TABLET', 8.39, 11.02, 133),
        ('BIO-D3 MAGNA', '', '', 'Tablet', 'TABLET', 18.36, 24.09, 115),
        ('BLADE 22', '', '', 'Tablet', 'SURGICAL', 3.45, 6.5, 85),
        ('BREATHOLLINE SR 200', '', '', 'Tablet', 'TABLET', 14.79, 16.76, 210),
        ('BREATHONAC AB', '', '', 'Tablet', 'TABLET', 13.21, 17.42, 120),
        ('BREATHONAC TAB', '', '', 'Tablet', 'TABLET', 11.97, 18.5, 170),
        ('BRO ZEDEX ACE TAB', '', '', 'Tablet', 'TABLET', 10.71, 14.06, 40),
        ('BRO-ZEDEX  SYP', '', '', 'Syrup', 'SYRUP', 135.18, 177.42, 6),
        ('BROZEDEX 100ML', '', '', 'Syrup', 'SYRUP', 135.18, 177.42, 1),
        ('BUDECORT 0.5 RESPULES', '', '', 'Tablet', 'GENERAL', 19.37, 25.42, 83),
        ('BYLENTA 40', '', '', 'Tablet', 'TABLET', 4.49, 7.37, 450),
        ('CALANGLE PLUS', '', '', 'Tablet', 'TABLET', 7.7, 10.22, 15),
        ('CALAPURE-LOTION', '', '', 'Cream/Ointment', 'LOTION', 96.95, 143.0, 5),
        ('CALCIGARD 10MG CAP', '', '', 'Capsule', 'CAPSULES', 0.77, 1.01, 50),
        ('CANDID CREAM', '', '', 'Cream/Ointment', 'CREAM/OINT/GEL', 72.0, 100.8, 2),
        ('CARIPAPA TAB', '', '', 'Tablet', 'TABLET', 29.49, 38.71, 75),
        ('CEFBACT T 1GM INJ', '', '', 'Injection', 'INJECTION', 37.0, 324.24, 132),
        ('CEREBOLIN P', '', '', 'Tablet', 'TABLET', 42.5, 59.5, 110),
        ('CERVICAL COLLAR (DELUX)', '', '', 'Tablet', 'GENERAL', 100.48, 300.0, 3),
        ('CERVICALCOLLAR M', '', '', 'Tablet', 'SURGICAL', 100.48, 300.0, 1),
        ('CERVICALCOLLAR S', '', '', 'Tablet', 'SURGICAL', 100.48, 300.0, 2),
        ('CETABLOC 10 TAB', '', '', 'Tablet', 'TABLET', 5.14, 7.2, 165),
        ('CEZOSAL 1500 IV  INJ', '', '', 'Injection', 'INJECTION', 65.0, 628.0, 19),
        ('CHYMORAL FORTE TABS', '', '', 'Tablet', 'TABLET', 17.82, 24.95, 5),
        ('CHYNACT DS', '', '', 'Tablet', 'TABLET', 21.36, 29.9, 20),
        ('CIFRAN 500MG TABS', '', '', 'Tablet', 'TABLET', 3.39, 4.75, 15),
        ('CILACAR T', '', '', 'Tablet', 'TABLET', 13.51, 18.91, 56),
        ('CILIDIN 10', '', '', 'Tablet', 'TABLET', 6.81, 10.92, 130),
        ('CILIDIN 5', '', '', 'Tablet', 'TABLET', 3.61, 6.18, 160),
        ('CIPLOX D E/E DROPS', '', '', 'Eye Drops', 'EYE/EAR DROP', 12.31, 17.24, 4),
        ('CIPONA 200 DT', '', '', 'Tablet', 'TABLET', 17.14, 22.5, 184),
        ('CIPONA CL TAB', '', '', 'Tablet', 'TABLET', 25.71, 33.75, 145),
        ('CITRALKA SYP 100ML', '', '', 'Syrup', 'SYRUP', 99.37, 130.43, 13),
        ('CITRAVITE XT TAB', '', '', 'Tablet', 'TABLET', 6.33, 8.31, 15),
        ('CIZASPA X TAB', '', '', 'Tablet', 'TABLET', 10.1, 14.14, 70),
        ('CLAMIN INJ 600MG', '', '', 'Injection', 'INJECTION', 63.96, 258.9, 4),
        ('CLAVAM 1.2G IV', '', '', 'Tablet', 'GENERAL', 114.76, 151.33, 36),
        ('CLINDASURE 300', '', '', 'Tablet', 'TABLET', 22.69, 29.79, 28),
        ('CLONAFIT - PLUS', '', '', 'Tablet', 'TABLET', 12.95, 17.02, 115),
        ('CLOPITAB 150GM TAB', '', '', 'Tablet', 'TABLET', 10.48, 14.67, 24),
        ('CLOPITAB CV GOLD 40', '', '', 'Capsule', 'CAPSULES', 12.53, 16.45, 80),
        ('COMBITHER AT 120MG', '', '', 'Injection', 'INJECTION', 363.55, 508.97, 8),
        ('CORDARONE X 200MG TABS', '', '', 'Tablet', 'TABLET', 13.81, 19.34, 60),
        ('CORTEL LN', '', '', 'Tablet', 'TABLET', 10.11, 13.88, 120),
        ('CORTEL TRIO', '', '', 'Tablet', 'RUBBER SHEET', 6.88, 9.64, 185),
        ('CORT-S 100MG INJ', '', '', 'Injection', 'INJECTION', 15.38, 47.7, 91),
        ('COTTON 125GM', '', '', 'Tablet', 'DISPOSALS', 69.0, 140.0, 3),
        ('CRINOVIT 9G', '', '', 'Tablet', 'TABLET', 18.29, 24.0, 178),
        ('DEPIN 10 CAPS', '', '', 'Capsule', 'CAPSULES', 0.77, 1.01, 45),
        ('DEXONA AMP', '', '', 'Injection', 'AMPLE', 8.28, 11.59, 32),
        ('DICLOTAL AQ INJ', '', '', 'Injection', 'AMPLE', 19.4, 27.0, 4),
        ('DICLOTAL FORTE GEL', '', '', 'Cream/Ointment', 'CREAM/OINT/GEL', 89.29, 125.0, 1),
        ('DILNIP 10TAB', '', '', 'Tablet', 'TABLET', 11.72, 15.46, 95),
        ('DILNIP TRIO TAB', '', '', 'Tablet', 'TABLET', 20.91, 27.45, 40),
        ('DIPPER XL', '', '', 'Tablet', 'DIPPER', 28.33, 64.9, 10),
        ('DISPOVAN NEEDLE 26G', '', '', 'Tablet', 'GENERAL', 0.87, 2.0, 200),
        ('DNS 500ML', '', '', 'Syrup', 'IV FLUIADS', 32.0, 95.78, 9),
        ('DOLO 650 TABS', '', '', 'Tablet', 'TABLET', 1.63, 2.14, 795),
        ('DORA 3ML', '', '', 'Tablet', 'SYRINGE', 2.05, 16.13, 200),
        ('DOXT-SL CAP', '', '', 'Capsule', 'CAPSULES', 10.38, 14.53, 35),
        ('DRESSING PAD 10CM*20', '', '', 'Tablet', 'SURGICAL', 10.5, 70.0, 26),
        ('DROTAN-MF', '', '', 'Tablet', 'TABLET', 12.4, 15.5, 115),
        ('DROTIN M TABS', '', '', 'Tablet', 'TABLET', 18.39, 24.14, 60),
        ('DULCOFLEX SUPPOSITIRIES', '', '', 'Powder', 'SUPPOSITAR', 0.99, 1.24, 57),
        ('DUOLIN RESPULES', '', '', 'Inhaler', 'RESPULES', 19.54, 25.65, 95),
        ('DUPHALAC 150 ML  SYP', '', '', 'Syrup', 'SYRUP', 150.0, 196.87, 6),
        ('DUPHALAC SYP 250ML', '', '', 'Syrup', 'SYRUP', 242.75, 322.0, 1),
        ('DYNA  ABDOMINAL  BELT', '', '', 'Tablet', 'GENERAL', 462.0, 840.0, 3),
        ('DYNA KNEE CAP', '', '', 'Capsule', 'CAPSULES', 244.12, 465.0, 4),
        ('DYTOR -10 MG TAB', '', '', 'Tablet', 'TABLET', 5.38, 7.06, 120),
        ('DYTOR -5MG TABS', '', '', 'Tablet', 'TABLET', 3.76, 4.93, 60),
        ('DYTOR PLUS 10MG TAB', '', '', 'Tablet', 'TABLET', 5.52, 7.51, 163),
        ('EASY FIX PLASTER', '', '', 'Tablet', 'PLASTER', 6.8, 47.0, 47),
        ('ECG PAPER (B)', '', '', 'Tablet', 'PAPER', 280.0, 300.0, 3),
        ('ECOSPRIN 150MG CAP', '', '', 'Capsule', 'CAPSULES', 0.62, 0.81, 112),
        ('ECOSPRIN AV 75MG CAP', '', '', 'Capsule', 'CAPSULES', 3.26, 4.08, 300),
        ('ECOSPRIN GOLD 40MG', '', '', 'Tablet', 'TABLET', 13.77, 17.21, 20),
        ('EFECTAL S 1500', '', '', 'Injection', 'INJECTION', 45.0, 193.5, 11),
        ('EFECTAL TZ', '', '', 'Injection', 'INJECTION', 41.0, 316.0, 1),
        ('ELDOPER  CAPS', '', '', 'Tablet', 'TABLET', 3.03, 3.98, 195),
        ('EMBETA XR 25MG TAB', '', '', 'Tablet', 'TABLET', 3.36, 4.7, 360),
        ('ENEMA', '', '', 'Syrup', 'LIQUIDS', 18.5, 80.0, 3),
        ('ENZOMAC OINTMENT 5GM', '', '', 'Cream/Ointment', 'OINTMENT', 82.55, 108.35, 2),
        ('ENZOMAC TAB', '', '', 'Tablet', 'TABLET', 19.47, 27.26, 150),
        ('ETIX PLUS', '', '', 'Tablet', 'TABLET', 20.05, 26.32, 100),
        ('ETOQUICK 400TAB', '', '', 'Tablet', 'TABLET', 23.22, 32.5, 74),
        ('ETOZAC - MR', '', '', 'Tablet', 'TABLET', 21.9, 28.73, 365),
        ('EXAMINATION GLOVES', '', '', 'Tablet', 'GLOVES', 3.03, 19.08, 235),
        ('FEBUGET 40MG TAB', '', '', 'Tablet', 'TABLET', 11.67, 15.38, 45),
        ('FEBUMAC 40', '', '', 'Tablet', 'TABLET', 11.21, 14.72, 60),
        ('FENOMUST', '', '', 'Tablet', 'TABLET', 13.2, 17.52, 240),
        ('FINGER COT S,M,L (DYNA)', '', '', 'Tablet', 'SURGICAL', 90.0, 150.0, 3),
        ('FLAGYL 400MG TABS', '', '', 'Tablet', 'TABLET', 1.22, 1.7, 25),
        ('FLEXABENZ GEL', '', '', 'Cream/Ointment', 'OINTMENT', 130.71, 171.56, 8),
        ('FLEXI MASK ADULT', '', '', 'Tablet', 'SURGICAL', 38.4, 323.46, 10),
        ('FOLEYS CATHATER 14 (RAMSON)', '', '', 'Tablet', 'SURGICAL', 26.0, 167.0, 17),
        ('FOLEYS CATHETER 16 NO', '', '', 'Tablet', 'SURGICAL', 26.0, 154.0, 7),
        ('FOLITRAX 7.5MG TAB', '', '', 'Tablet', 'TABLET', 13.68, 17.95, 50),
        ('FOLVITE 5 MG TAB', '', '', 'Tablet', 'TABLET', 1.24, 1.72, 8015),
        ('FORACORT 200MG INHALER', '', '', 'Inhaler', 'INHELER', 288.96, 379.25, 3),
        ('FORACORT 400 INHALER', '', '', 'Inhaler', 'INHELER', 329.27, 460.98, 2),
        ('FORCAN 150MG TABS', '', '', 'Tablet', 'TABLET', 9.65, 13.51, 24),
        ('GABALOY NT', '', '', 'Tablet', 'TABLET', 15.81, 27.05, 155),
        ('GABALOY NT 100', '', '', 'Tablet', 'TABLET', 7.99, 12.81, 114),
        ('GABANEURON NT 100 TAB', '', '', 'Tablet', 'TABLET', 8.7, 11.66, 249),
        ('GABAPIN-ME 100MG TABS', '', '', 'Tablet', 'TABLET', 10.24, 13.44, 155),
        ('GABAPIN-NT 200', '', '', 'Tablet', 'TABLET', 15.0, 19.69, 205),
        ('GEMER DAPA XR 10/2/1000', '', '', 'Tablet', 'TABLET', 13.32, 17.48, 105),
        ('GEMER V2', '', '', 'Tablet', 'TABLET', 14.24, 18.69, 90),
        ('GLIMESTAR M1 FORTE', '', '', 'Tablet', 'TABLET', 6.42, 8.99, 60),
        ('GLIMESTAR M1 TAB', '', '', 'Tablet', 'TABLET', 5.36, 7.5, 90),
        ('GLIMESTAR M2 TAB', '', '', 'Tablet', 'TABLET', 6.71, 9.4, 100),
        ('GLIMESTAR M2FORTE', '', '', 'Tablet', 'TABLET', 8.01, 11.22, 30),
        ('GLIMITOS M1 FORTE TAB', '', '', 'Tablet', 'TABLET', 6.76, 9.31, 225),
        ('GLIMITOS M1 TAB', '', '', 'Tablet', 'TABLET', 5.54, 7.22, 28),
        ('GLIMITOS M2 FORTE TAB', '', '', 'Tablet', 'TABLET', 7.43, 9.75, 119),
        ('GLIMITOS M2 TAB', '', '', 'Tablet', 'TABLET', 6.79, 8.88, 75),
        ('GLIMITOS M3', '', '', 'Tablet', 'TABLET', 6.62, 8.69, 147),
        ('GLIMITOS M3 FORTE', '', '', 'Tablet', 'TABLET', 7.86, 10.31, 180),
        ('GLIMITOS M4 FORTE', '', '', 'Tablet', 'TABLET', 8.52, 11.93, 74),
        ('GLITARAY M2', '', '', 'Tablet', 'TABLET', 6.93, 11.02, 405),
        ('GLUCI 10ML', '', '', 'Injection', 'INJECTION', 24.74, 91.5, 7),
        ('GLUCONORM G0.5 TAB', '', '', 'Tablet', 'TABLET', 10.32, 13.55, 170),
        ('GLUCONORM G1', '', '', 'Tablet', 'TABLET', 11.8, 15.49, 190),
        ('GLYCERIN', '', '', 'Tablet', 'GENERAL', 31.73, 73.62, 8),
        ('GLYCERIN 200 MG', '', '', 'Syrup', 'LIQUIDS', 45.0, 200.0, 1),
        ('GLYCOMET  SR 500MG TAB', '', '', 'Tablet', 'TABLET', 2.13, 2.8, 150),
        ('GLYCOMET 250MG TABS', '', '', 'Tablet', 'TABLET', 1.23, 1.73, 110),
        ('GLYCOMET -500MG TAB', '', '', 'Tablet', 'TABLET', 1.46, 2.04, 20),
        ('GLYCOMET GP 0.5MG TAB', '', '', 'Tablet', 'TABLET', 4.42, 5.9, 80),
        ('GLYCOMET GP 1GM', '', '', 'Tablet', 'TABLET', 6.24, 8.4, 120),
        ('GLYCOMET GP 2MG TAB', '', '', 'Tablet', 'TABLET', 5.45, 11.9, 75),
        ('GLYCOMET GP1 FORTE.', '', '', 'Tablet', 'TABLET', 6.46, 9.05, 10),
        ('GLYCOMET TRIO 1', '', '', 'Tablet', 'TABLET', 12.23, 17.12, 60),
        ('GZOR M1', '', '', 'Tablet', 'TABLET', 4.7, 8.05, 589),
        ('GZOR M3 FORTE', '', '', 'Tablet', 'TABLET', 7.04, 11.67, 639),
        ('H2O2 100ML', '', '', 'Tablet', 'SURGICAL', 4.75, 25.0, 11),
        ('HALF NS 500ML', '', '', 'Syrup', 'IV FLUIADS', 36.0, 230.0, 39),
        ('HCQS 200 TABS', '', '', 'Tablet', 'TABLET', 5.18, 7.25, 50),
        ('HIFENAC P TABS', '', '', 'Tablet', 'TABLET', 5.43, 7.27, 300),
        ('HQL 60K', '', '', 'Tablet', 'TABLET', 18.77, 24.61, 104),
        ('HUMAN ACTRAPID 40', '', '', 'Injection', 'INJECTION', 145.11, 181.39, 8),
        ('HUMAN MIXTARD 40 INJ', '', '', 'Injection', 'INJECTION', 67.15, 83.94, 168),
        ('HUMINSULIN "R" CARTIGES', '', '', 'Tablet', 'GENERAL', 412.72, 515.8, 5),
        ('HYOCIMAX INJ', '', '', 'Injection', 'INJECTION', 11.43, 16.0, 8),
        ('IMAX XT SYP', '', '', 'Syrup', 'SYRUP', 132.15, 173.44, 9),
        ('INDERAL 10MG TAB', '', '', 'Tablet', 'TABLET', 1.06, 1.4, 65),
        ('INDERAL 20MG', '', '', 'Tablet', 'TABLET', 2.56, 3.58, 60),
        ('INSUGEN 30/70 REFIL', '', '', 'Tablet', 'GENERAL', 250.27, 312.84, 20),
        ('INSUGEN N REFIL', '', '', 'Injection', 'INJECTION', 207.16, 258.95, 5),
        ('INSUGEN R VOIL', '', '', 'Injection', 'INJECTION', 139.74, 174.68, 1),
        ('INSUGEN-30/70', '', '', 'Injection', 'INJECTION', 455.2, 569.0, 1),
        ('INSUGEN-R REFILL', '', '', 'Tablet', 'GENERAL', 207.16, 258.8, 1),
        ('INTAFOL D CAP', '', '', 'Tablet', 'TABLET', 18.36, 25.7, 30),
        ('INTAGLIP M TAB', '', '', 'Tablet', 'TABLET', 9.57, 13.4, 10),
        ('INTRA-CATH 20G', '', '', 'Tablet', 'GENERAL', 12.0, 147.0, 9),
        ('INTRA-CATH 22NO', '', '', 'Tablet', 'GENERAL', 8.0, 217.0, 31),
        ('ISOFIT 10', '', '', 'Tablet', 'TABLET', 42.79, 59.9, 30),
        ('IV SET', '', '', 'Syrup', 'INFUSION', 12.49, 217.89, 19),
        ('IVEPRED 40 INJ', '', '', 'Injection', 'INJECTION', 37.15, 52.01, 9),
        ('JAYCOT COTTON 400', '', '', 'Tablet', 'SURGICAL', 168.91, 370.0, 1),
        ('JMS MEDI TAPE 12MM', '', '', 'Powder', 'SACHETS', 17.7, 50.0, 23),
        ('JOINT PLUS - R', '', '', 'Capsule', 'CAPSULES', 13.6, 18.9, 40),
        ('JUCINAC 600 TAB', '', '', 'Tablet', 'TABLET', 21.24, 27.7, 100),
        ('JUMBO BANDAGE 4', '', '', 'Tablet', 'SURGICAL', 11.2, 43.0, 20),
        ('KNEE CAP (ROYAL) S, M, L', '', '', 'Tablet', 'SURGICAL', 90.0, 310.0, 1),
        ('KNEE CAPS (SMALL)', '', '', 'Capsule', 'CAPSULES', 84.5, 300.0, 1),
        ('LABLOL 20MG', '', '', 'Tablet', 'TABLET', 79.75, 227.0, 1),
        ('LABLOL INJ', '', '', 'Injection', 'INJECTION', 74.97, 223.5, 1),
        ('LASIX 4ML INJ', '', '', 'Injection', 'INJECTION', 11.3, 13.39, 11),
        ('LAZINE  M TAB', '', '', 'Tablet', 'TABLET', 6.79, 8.91, 35),
        ('LEVERA 500MG TAB', '', '', 'Tablet', 'TABLET', 10.38, 14.54, 135),
        ('LEVERA RTU 1000', '', '', 'Injection', 'INJECTION', 158.52, 215.58, 7),
        ('LEVOCET 5MG TAB', '', '', 'Tablet', 'TABLET', 4.03, 5.29, 57),
        ('LEVOFLOX 500MG TABS', '', '', 'Tablet', 'TABLET', 7.32, 9.61, 20),
        ('LEVOLIN 0.31MG RESP', '', '', 'Inhaler', 'RESPULES', 5.3, 6.53, 21),
        ('LEVOSIZ 5MG TAB', '', '', 'Tablet', 'TABLET', 1.6, 2.0, 50),
        ('LIBRIUM 10MG TABS', '', '', 'Tablet', 'TABLET', 8.18, 11.45, 45),
        ('LIBRIUM 25MG TAB', '', '', 'Tablet', 'TABLET', 12.45, 16.35, 95),
        ('LIMCEE ORANGE TABS', '', '', 'Tablet', 'TABLET', 1.25, 1.65, 106),
        ('LIV.52 DS 100ML', '', '', 'Cream/Ointment', 'CREAM/OINT/GEL', 171.42, 225.0, 5),
        ('LIVOGEN XT', '', '', 'Tablet', 'GENERAL', 15.09, 19.81, 90),
        ('LIZOFORCE IV', '', '', 'Tablet', 'GENERAL', 165.0, 511.0, 1),
        ('LNDIP T', '', '', 'Tablet', 'TABLET', 9.37, 12.3, 218),
        ('LNDIP-BETA 50', '', '', 'Tablet', 'TABLET', 10.13, 13.3, 900),
        ('LOX 2% INJECTION', '', '', 'Injection', 'INJECTION', 29.98, 34.93, 1),
        ('LOX 2% JELLY', '', '', 'Cream/Ointment', 'JELLY', 27.0, 36.28, 2),
        ('LOX HEAVY 5% AMP', '', '', 'Injection', 'INJECTION', 31.34, 40.75, 1),
        ('LOYZIDE-40MG', '', '', 'Tablet', 'TABLET', 3.69, 5.92, 95),
        ('LOYZIDE-40MG TAB', '', '', 'Tablet', 'TABLET', 3.36, 5.75, 135),
        ('LUMERAX 80MG', '', '', 'Tablet', 'TABLET', 20.64, 27.69, 27),
        ('LUPASE 10000 TAB', '', '', 'Tablet', 'TABLET', 20.22, 28.31, 80),
        ('M STRONG CS', '', '', 'Tablet', 'TABLET', 12.85, 20.61, 45),
        ('M STRONG PG', '', '', 'Tablet', 'TABLET', 8.14, 13.93, 435),
        ('MAGNEON 2ML', '', '', 'Injection', 'AMPLE', 8.23, 10.98, 9),
        ('MAGNESIUM SULPHATE POWDER 400GR', '', '', 'Tablet', 'SURGICAL', 37.67, 148.75, 4),
        ('MANITOL IV', '', '', 'Syrup', 'INFUSION', 31.88, 38.04, 18),
        ('MASK', '', '', 'Tablet', 'GENERAL', 2.5, 10.0, 94),
        ('MATILDA PG ER', '', '', 'Tablet', 'GENERAL', 16.28, 22.79, 15),
        ('MATILDA PLUS CAPS', '', '', 'Capsule', 'CAPSULES', 13.46, 17.31, 275),
        ('MECOONE - FORTE', '', '', 'Injection', 'INJECTION', 22.0, 225.0, 10),
        ('MECOONE PLUS INJ', '', '', 'Injection', 'INJECTION', 20.0, 190.0, 28),
        ('MEDIFLON 22G', '', '', 'Tablet', 'GENERAL', 11.58, 261.0, 100),
        ('MEDROL 4MG TAB', '', '', 'Tablet', 'TABLET', 4.11, 5.47, 65),
        ('MEFTAL SPAS TABS', '', '', 'Tablet', 'TABLET', 3.71, 5.2, 46),
        ('MEGA CV 1.2GM', '', '', 'Injection', 'INJECTION', 115.3, 151.32, 2),
        ('MEGA CV 625 MG TAB', '', '', 'Tablet', 'TABLET', 11.33, 15.87, 150),
        ('MEGACHOLIN 2ML', '', '', 'Injection', 'INJECTION', 259.62, 389.2, 5),
        ('MEGAZOLID 600 TAB', '', '', 'Tablet', 'TABLET', 268.18, 375.45, 36),
        ('MERO O 200', '', '', 'Tablet', 'TABLET', 69.64, 97.5, 70),
        ('MERO-1GM INJ', '', '', 'Injection', 'INJECTION', 656.7, 919.39, 6),
        ('METHYFILL- PLUS INJ', '', '', 'Injection', 'INJECTION', 28.1, 259.0, 77),
        ('METOSARTAN 25', '', '', 'Tablet', 'TABLET', 13.5, 18.9, 90),
        ('METOSARTAN 50 TABS', '', '', 'Tablet', 'TABLET', 15.86, 20.9, 160),
        ('METOZOX 25', '', '', 'Tablet', 'TABLET', 2.75, 4.7, 330),
        ('METRIS 100ML INJ', '', '', 'Syrup', 'IV FLUIADS', 14.5, 22.05, 23),
        ('METROGYL 400 TABS', '', '', 'Tablet', 'TABLET', 0.45, 1.74, 14),
        ('METROGYL 400MG TABS', '', '', 'Tablet', 'TABLET', 1.48, 1.8, 590),
        ('MEXTIL 500', '', '', 'Tablet', 'TABLET', 39.28, 55.0, 13),
        ('MGD3 TABS', '', '', 'Tablet', 'TABLET', 21.07, 27.66, 220),
        ('MICRO I.V. SET', '', '', 'Tablet', 'GENERAL', 16.99, 171.0, 24),
        ('MINGLE D', '', '', 'Tablet', 'TABLET', 12.0, 16.8, 250),
        ('MONOCEF 1GM INJ', '', '', 'Injection', 'INJECTION', 50.77, 66.63, 9),
        ('MONTENA BL', '', '', 'Tablet', 'TABLET', 11.36, 14.9, 120),
        ('MUCIFLO TAB', '', '', 'Tablet', 'TABLET', 12.5, 17.5, 5),
        ('MUCINAC 600 MG TAB', '', '', 'Tablet', 'TABLET', 27.9, 36.62, 70),
        ('NACETAM AMP', '', '', 'Injection', 'INJECTION', 47.0, 140.75, 8),
        ('NAXDOM 250MG TAB', '', '', 'Tablet', 'TABLET', 5.43, 7.6, 1),
        ('NAXDOM 500MG TAB', '', '', 'Tablet', 'TABLET', 8.95, 11.75, 80),
        ('NEBISTAR SA TAB', '', '', 'Tablet', 'TABLET', 19.24, 26.94, 105),
        ('NEBULIZER MACHINE', '', '', 'Tablet', 'NEBULIZER MACHINE', 940.0, 2099.5, 2),
        ('NEO MERCAZOLE 5MG TAB', '', '', 'Tablet', 'TABLET', 231.34, 323.88, 1),
        ('NEOMOL 2ML AMP', '', '', 'Injection', 'AMPLE', 6.61, 8.89, 10),
        ('NEOMOL IV', '', '', 'Injection', 'INJECTION', 26.5, 574.0, 5),
        ('NEPHROHEAL TAB', '', '', 'Tablet', 'TABLET', 10.9, 14.31, 68),
        ('NERVCON PLUS TAB', '', '', 'Tablet', 'TABLET', 17.14, 22.5, 265),
        ('NERVITE DX', '', '', 'Tablet', 'TABLET', 13.71, 18.0, 100),
        ('NETICOL-2ML ING', '', '', 'Injection', 'INJECTION', 44.31, 209.71, 28),
        ('NEUROTIK LC', '', '', 'Tablet', 'TABLET', 13.56, 17.8, 407),
        ('NEXITO PLUS', '', '', 'Tablet', 'TABLET', 9.71, 12.75, 20),
        ('NIPRO 10ML', '', '', 'Injection', 'INJECTION', 6.92, 27.5, 140),
        ('NIPRO 3ML', '', '', 'Injection', 'INJECTION', 3.96, 15.47, 22),
        ('NIPRO 5ML', '', '', 'Injection', 'INJECTION', 5.23, 276.83, 207),
        ('NITRILE GLOVES', '', '', 'Tablet', 'GLOVES', 3.47, 18.18, 132),
        ('NS 100ML', '', '', 'Syrup', 'IV FLUIADS', 21.98, 44.93, 80),
        ('NS 250ML', '', '', 'Syrup', 'IV FLUIADS', 22.97, 28.25, 6),
        ('NS 500ML 1', '', '', 'Syrup', 'IV FLUIADS', 34.98, 93.95, 41),
        ('NUMINE 100 TAB', '', '', 'Tablet', 'TABLET', 2.73, 4.77, 70),
        ('NUSAFE 10ML', '', '', 'Injection', 'INJECTION', 3.9, 35.0, 18),
        ('NUSAFE 5ML', '', '', 'Injection', 'INJECTION', 2.5, 23.0, 133),
        ('OFLOX I.V', '', '', 'Tablet', 'GENERAL', 164.91, 216.45, 20),
        ('OLMEZEST 40 TAB', '', '', 'Tablet', 'TABLET', 19.07, 26.7, 139),
        ('OLMEZEST H 40', '', '', 'Tablet', 'TABLET', 22.16, 30.23, 363),
        ('OMNICEF-O 200MG TAB', '', '', 'Tablet', 'TABLET', 7.82, 10.95, 15),
        ("ONE TOUCH HORIZON STRIPS 25'S", '', '', 'Tablet', 'GENERAL', 564.98, 633.0, 1),
        ('ONE TOUCH SELECT PLUS', '', '', 'Tablet', 'GENERAL', 20.44, 23.9, 75),
        ('ONE TOUCH STRIPS   50S', '', '', 'Tablet', 'GENERAL', 27.43, 32.6, 252),
        ('OPTINEURON INJ 3ML', '', '', 'Injection', 'INJECTION', 9.93, 13.9, 27),
        ('OROFER XT TABS', '', '', 'Tablet', 'TABLET', 24.21, 33.9, 2),
        ('ORS APPLE 200', '', '', 'Tablet', 'SURGICAL', 16.3, 31.5, 5),
        ('ORS ORANGE', '', '', 'Tablet', 'GENERAL', 16.33, 31.55, 106),
        ('ORTHOCORT 6', '', '', 'Tablet', 'TABLET', 11.38, 14.93, 162),
        ('ORVIFER - XT', '', '', 'Tablet', 'TABLET', 15.92, 19.9, 90),
        ('OXRAMET S XR 1000', '', '', 'Tablet', 'TABLET', 16.31, 21.66, 211),
        ('OXY SET MASK (A)', '', '', 'Tablet', 'SURGICAL', 23.0, 230.0, 8),
        ('PACIMOL 500', '', '', 'Tablet', 'TABLET', 0.74, 1.03, 1247),
        ('PACIMOL 650MG TAB', '', '', 'Tablet', 'TABLET', 1.63, 2.14, 4),
        ('PACIMOL IV', '', '', 'Injection', 'INJECTION', 50.0, 217.03, 16),
        ('PANSEC IV  40', '', '', 'Injection', 'INJECTION', 15.5, 53.88, 63),
        ('PANTAKIND 40MG INJ', '', '', 'Tablet', 'TABLET', 41.05, 53.88, 31),
        ('PANTIN 40MG TABS', '', '', 'Tablet', 'TABLET', 5.28, 6.93, 775),
        ('PANTIN-D CAPS', '', '', 'Capsule', 'CAPSULES', 7.14, 9.36, 280),
        ('PANTOP DSP CAPS', '', '', 'Capsule', 'CAPSULES', 10.0, 14.0, 7),
        ('PANTOP DSR CAPS', '', '', 'Capsule', 'CAPSULES', 10.52, 14.73, 68),
        ('PM O LINE 100 CM', '', '', 'Tablet', 'SURGICAL', 27.0, 365.0, 5),
        ('PODIME CV325', '', '', 'Tablet', 'TABLET', 25.89, 33.98, 100),
        ('POTCL 10ML', '', '', 'Injection', 'INJECTION', 13.8, 26.7, 10),
        ('POVIKEM GARGLE', '', '', 'Cream/Ointment', 'GEL', 34.98, 198.0, 1),
        ('PRASUDOC 10', '', '', 'Tablet', 'TABLET', 20.85, 27.36, 140),
        ('PREDMET 4MG TABS', '', '', 'Tablet', 'TABLET', 4.57, 6.0, 25),
        ('PREGALEO M', '', '', 'Tablet', 'TABLET', 7.78, 10.58, 370),
        ('PREGASTAR D 75', '', '', 'Tablet', 'GENERAL', 15.64, 21.89, 30),
        ('PRIMERICH-CZS TAB', '', '', 'Tablet', 'TABLET', 7.64, 11.25, 1575),
        ('PROLENE 1-0 NW805', '', '', 'Tablet', 'SHEET', 209.55, 381.0, 1),
        ('PROLOMET XL 50 TABS', '', '', 'Tablet', 'TABLET', 4.73, 6.36, 105),
        ('PROTERA', '', '', 'Tablet', 'GENERAL', 11.35, 14.9, 22),
        ('PROTITROX POWDER', '', '', 'Powder', 'POWDER', 74.28, 511.65, 5),
        ('PROXYM MR TAB', '', '', 'Tablet', 'TABLET', 27.52, 38.53, 40),
        ('PULMOCLEAR TAB', '', '', 'Tablet', 'TABLET', 14.67, 20.53, 15),
        ('Q-CAL TAB', '', '', 'Tablet', 'TABLET', 6.33, 8.87, 210),
        ('RABEZOX-D', '', '', 'Tablet', 'TABLET', 8.46, 13.57, 52),
        ('RABISHAN DSR', '', '', 'Tablet', 'TABLET', 7.07, 9.28, 45),
        ('REHEPTIN TAB', '', '', 'Tablet', 'TABLET', 22.86, 30.67, 60),
        ('REMETOR 10', '', '', 'Tablet', 'TABLET', 3.28, 5.61, 290),
        ('REMETOR 20', '', '', 'Tablet', 'TABLET', 5.92, 10.13, 225),
        ('REMETOR-F TABS', '', '', 'Tablet', 'TABLET', 10.17, 16.31, 290),
        ('RESPIRO METER', '', '', 'Tablet', 'GENERAL', 125.0, 736.5, 2),
        ('RESTYL 0.25MG TABS', '', '', 'Tablet', 'TABLET', 1.75, 2.33, 90),
        ('RESTYL 0.5MG TABS', '', '', 'Tablet', 'TABLET', 3.29, 4.32, 22),
        ('RIFGUARD 200 TAB', '', '', 'Tablet', 'TABLET', 12.46, 17.45, 40),
        ('RL 500 ML', '', '', 'Syrup', 'IV FLUIADS', 26.0, 63.26, 22),
        ('ROMO JET 50 ML', '', '', 'Tablet', 'GENERAL', 18.0, 43.0, 10),
        ('ROMOJET 3ML SYRINGE', '', '', 'Tablet', 'GENERAL', 2.06, 9.9, 200),
        ('ROPLENE 5-0 RC 880', '', '', 'Tablet', 'NEEDLE', 147.2, 294.4, 2),
        ('ROSLOY ASP 10/75 .', '', '', 'Tablet', 'TABLET', 7.12, 11.46, 315),
        ('ROSLOY GOLD 10', '', '', 'Tablet', 'TABLET', 11.45, 19.59, 225),
        ('ROSUCORD ASP', '', '', 'Tablet', 'TABLET', 6.4, 8.9, 10),
        ('ROSULESS 10', '', '', 'Tablet', 'TABLET', 5.51, 7.23, 360),
        ('ROSULESS C 10', '', '', 'Tablet', 'TABLET', 11.38, 14.93, 120),
        ('ROSULESS F TAB', '', '', 'Tablet', 'TABLET', 16.53, 21.69, 270),
        ('ROYAL BELT', '', '', 'Tablet', 'SURGICAL', 221.32, 630.0, 1),
        ('ROZANGLE -F10', '', '', 'Tablet', 'TABLET', 12.4, 16.5, 200),
        ('ROZAVEL F TABS', '', '', 'Tablet', 'TABLET', 21.29, 27.94, 105),
        ('ROZUTOS CV 10', '', '', 'Tablet', 'TABLET', 12.14, 16.2, 120),
        ('RUPOD -200DT', '', '', 'Tablet', 'TABLET', 14.3, 18.75, 160),
        ('RUPOD-CV', '', '', 'Tablet', 'TABLET', 25.0, 32.81, 10),
        ('RYLES TUBE  14G', '', '', 'Tablet', 'GENERAL', 10.5, 68.0, 6),
        ('RYLES TUBE 12NO', '', '', 'Tablet', 'SURGICAL', 13.5, 72.0, 2),
        ('SANTOMOX 625', '', '', 'Tablet', 'TABLET', 14.9, 19.55, 231),
        ('SANTOPOD 200', '', '', 'Tablet', 'TABLET', 22.22, 29.15, 170),
        ('SANTOPOD CV 200', '', '', 'Tablet', 'TABLET', 24.22, 31.78, 10),
        ('SARTEL-H TAB', '', '', 'Tablet', 'TABLET', 15.19, 20.51, 135),
        ('SCALP VAIN SET 22G', '', '', 'Tablet', 'GENERAL', 5.74, 25.31, 89),
        ('SEFTRI-TZ', '', '', 'Injection', 'INJECTION', 100.0, 299.0, 4),
        ('SHELCAL 500MG', '', '', 'Tablet', 'TABLET', 7.55, 10.57, 30),
        ('SILVEREX 10GM', '', '', 'Cream/Ointment', 'CREAM/OINT/GEL', 8.79, 12.3, 20),
        ('SITANIP 100', '', '', 'Tablet', 'TABLET', 8.93, 12.5, 105),
        ('SITARA D 100/10', '', '', 'Tablet', 'TABLET', 16.42, 21.54, 90),
        ('SITARA DM', '', '', 'Tablet', 'TABLET', 16.36, 21.49, 70),
        ('SITARA M 100/500', '', '', 'Tablet', 'TABLET', 12.48, 16.38, 70),
        ('SITARA M 50/500', '', '', 'Tablet', 'TABLET', 9.36, 12.28, 150),
        ('SNAKE VENOM ANTISERUM I.P', '', '', 'Injection', 'INJECTION', 425.0, 625.59, 10),
        ('SOBIINIX DS TAB', '', '', 'Tablet', 'TABLET', 4.91, 6.28, 195),
        ('SOBINIX TAB 500', '', '', 'Tablet', 'TABLET', 2.93, 3.74, 75),
        ('SODAC AMP 25ML', '', '', 'Injection', 'AMPLE', 24.15, 31.5, 1),
        ('SOFT COLLER-LARGE', '', '', 'Tablet', 'GENERAL', 120.0, 285.0, 1),
        ('SOFT COLLER-MEDIUM', '', '', 'Tablet', 'GENERAL', 120.0, 285.0, 1),
        ('SOFT D3 TAB', '', '', 'Tablet', 'TABLET', 23.23, 32.5, 4),
        ('SOMPRAZ 40 MG TAB', '', '', 'Tablet', 'TABLET', 9.3, 12.2, 150),
        ('SOMPRAZ IV 40MG', '', '', 'Injection', 'INJECTION', 34.0, 106.88, 50),
        ('SPINFREE TAB', '', '', 'Tablet', 'TABLET', 11.0, 14.44, 57),
        ('SPINVERT 16MG', '', '', 'Tablet', 'TABLET', 8.94, 11.82, 193),
        ('SPIROMETER (HUDSON)', '', '', 'Tablet', 'GENERAL', 400.0, 700.0, 1),
        ('SPORLAC -DS TABS', '', '', 'Tablet', 'TABLET', 6.83, 8.97, 283),
        ('STAMLO 5MG TABS', '', '', 'Tablet', 'TABLET', 2.02, 2.8, 120),
        ('STICK O PLAST', '', '', 'Tablet', 'PAPER PLASTER', 9.52, 22.0, 5),
        ('STRAUSS PAD 10*10', '', '', 'Tablet', 'DISPOSALS', 45.0, 70.0, 15),
        ('STRAUSS PAD 10CM*20CM', '', '', 'Powder', 'SACHETS', 13.5, 70.0, 27),
        ('STRAUSS PAD 7*5 CM', '', '', 'Tablet', 'DISPOSALS', 6.9, 22.0, 10),
        ('SUCRAFIL O GEL SYP', '', '', 'Syrup', 'SYRUP', 224.76, 295.0, 7),
        ('SUGARAY GM 50/2/1000', '', '', 'Tablet', 'TABLET', 9.64, 15.46, 270),
        ('SUGARAY M 50/500', '', '', 'Tablet', 'TABLET', 6.36, 10.89, 240),
        ('SUPRACAL 2000', '', '', 'Tablet', 'TABLET', 15.39, 20.2, 240),
        ('SUPRACAL TABS', '', '', 'Tablet', 'TABLET', 10.24, 13.44, 503),
        ('SUPRIDOL 2ML', '', '', 'Injection', 'INJECTION', 9.0, 26.8, 92),
        ('SURGICAL BLADE-11', '', '', 'Tablet', 'SURGICAL', 2.8, 6.0, 92),
        ('SURGICAL BLADE-22', '', '', 'Tablet', 'SURGICAL', 2.8, 6.0, 95),
        ('SURGICAL GLOVE', '', '', 'Tablet', 'SURGICAL', 14.0, 97.0, 3),
        ('TAH 40 TAB', '', '', 'Tablet', 'TABLET', 12.1, 16.93, 60),
        ('TAMSIFLO', '', '', 'Tablet', 'TABLET', 11.17, 15.64, 61),
        ('TAMSIFLO D', '', '', 'Tablet', 'TABLET', 16.99, 32.32, 165),
        ('TAZOFAST 4.5GM', '', '', 'Injection', 'INJECTION', 95.0, 426.68, 13),
        ('T-BACT OINT', '', '', 'Cream/Ointment', 'CREAM/OINT/GEL', 82.56, 108.36, 2),
        ('TECZINE-10MG TAB', '', '', 'Tablet', 'TABLET', 11.48, 14.75, 95),
        ('TELDAWN BETA 40/50', '', '', 'Tablet', 'TABLET', 14.07, 19.7, 90),
        ('TELDAWN H', '', '', 'Tablet', 'TABLET', 8.68, 11.39, 270),
        ('TELISTA CH', '', '', 'Tablet', 'TABLET', 14.13, 18.54, 60),
        ('TELLZY 40MG', '', '', 'Tablet', 'TABLET', 5.5, 7.32, 510),
        ('TELLZY ACH', '', '', 'Tablet', 'TABLET', 13.3, 17.46, 280),
        ('TELMITOS 20 TAB', '', '', 'Tablet', 'TABLET', 2.5, 3.5, 150),
        ('TELMITOS 40 TAB', '', '', 'Tablet', 'TABLET', 5.0, 6.56, 195),
        ('TELMITOS CT 40 TAB', '', '', 'Tablet', 'TABLET', 8.36, 10.97, 135),
        ('TELSYD-40', '', '', 'Tablet', 'TABLET', 4.71, 6.19, 360),
        ('TELVAS 20', '', '', 'Tablet', 'TABLET', 2.83, 3.72, 180),
        ('TELVAS 40', '', '', 'Tablet', 'TABLET', 5.7, 7.99, 94),
        ('TELVAS H 40 TAB', '', '', 'Tablet', 'TABLET', 6.86, 9.25, 350),
        ('TELVAS H TAB', '', '', 'Tablet', 'TABLET', 7.07, 9.28, 100),
        ('TELZOX H', '', '', 'Tablet', 'TABLET', 9.71, 16.61, 270),
        ('TEMSAN LN TAB', '', '', 'Tablet', 'TABLET', 8.31, 10.91, 60),
        ('TEMSAN-40 TABS', '', '', 'Tablet', 'TABLET', 3.28, 4.59, 70),
        ('TENEBITE - M', '', '', 'Tablet', 'TABLET', 16.28, 21.37, 90),
        ('TENIVA 20', '', '', 'Tablet', 'TABLET', 9.02, 11.84, 90),
        ('TENIVA M', '', '', 'Tablet', 'TABLET', 17.65, 24.71, 70),
        ('TEXAKIND 5ML AMP', '', '', 'Injection', 'AMPLE', 41.78, 54.84, 1),
        ('TEXAKIND TAB', '', '', 'Tablet', 'TABLET', 11.91, 15.63, 20),
        ('THAISTA AMP', '', '', 'Injection', 'INJECTION', 17.2, 50.6, 24),
        ('THYRONORM 100MCG', '', '', 'Tablet', 'TABLET', 128.64, 174.46, 4),
        ('THYRONORM 12.5 TAB', '', '', 'Tablet', 'TABLET', 144.55, 196.04, 2),
        ('THYRONORM 125MG TAB', '', '', 'Tablet', 'TABLET', 165.06, 231.08, 1),
        ('THYRONORM 150MG', '', '', 'Tablet', 'GENERAL', 166.03, 217.91, 1),
        ('THYRONORM 25MG TABS', '', '', 'Tablet', 'TABLET', 141.26, 185.4, 3),
        ('THYRONORM 37.5 TAB', '', '', 'Tablet', 'TABLET', 143.15, 187.86, 2),
        ('THYRONORM 50 MG', '', '', 'Tablet', 'TABLET', 100.59, 140.83, 2),
        ('THYRONORM 50MG TABS', '', '', 'Tablet', 'TABLET', 100.59, 132.03, 4),
        ('THYRONORM 62.5 TAB', '', '', 'Tablet', 'TABLET', 157.24, 206.37, 2),
        ('THYRONORM 75', '', '', 'Tablet', 'TABLET', 140.17, 183.97, 3),
        ('THYRONORM 75MG', '', '', 'Tablet', 'TABLET', 140.17, 183.97, 2),
        ('THYRONORM 88 MCG', '', '', 'Tablet', 'TABLET', 160.97, 225.36, 1),
        ('T-MINE', '', '', 'Injection', 'INJECTION', 15.85, 50.6, 6),
        ('TOP BAN 15*3', '', '', 'Tablet', 'SURGICAL', 39.52, 250.82, 17),
        ('TOP BAND 10*10', '', '', 'Tablet', 'TABLET', 43.5, 199.0, 2),
        ('TOP CREPE 10CM', '', '', 'Tablet', 'GENERAL', 91.2, 341.0, 2),
        ('TOP CREPE 15CM', '', '', 'Tablet', 'GENERAL', 115.92, 455.0, 5),
        ('TOP O PLAST 10CM*1M', '', '', 'Tablet', 'SURGICAL', 78.0, 290.0, 10),
        ('TOPBAN 15CM*3M', '', '', 'Tablet', 'TABLET', 45.32, 289.0, 9),
        ("TOPCREPE 6'INCH", '', '', 'Tablet', 'SURGICAL', 300.0, 455.0, 1),
        ('TRENAXA  INJ', '', '', 'Injection', 'INJECTION', 54.83, 71.97, 5),
        ('TRENAXA 500 TABS', '', '', 'Tablet', 'TABLET', 15.09, 19.8, 8),
        ('TRENAXA 500MG TAB', '', '', 'Tablet', 'TABLET', 15.09, 19.8, 50),
        ('TROPINE AMP', '', '', 'Tablet', 'GENERAL', 39.69, 47.98, 1),
        ('TRULENE 843 1 RB', '', '', 'Tablet', 'SUTURES', 162.86, 361.92, 2),
        ('TRULON 2-0 3336', '', '', 'Tablet', 'SURGICAL', 88.28, 196.17, 2),
        ('TRYPACE - TH 4', '', '', 'Tablet', 'TABLET', 17.45, 22.9, 88),
        ('TRYPACE-SP', '', '', 'Tablet', 'TABLET', 10.73, 14.9, 10),
        ('TUSQ DX SYRUP', '', '', 'Syrup', 'SYRUP', 78.57, 103.13, 9),
        ('TUSQ-LS SYP', '', '', 'Syrup', 'SYRUP', 82.14, 107.81, 7),
        ('UDAPA 10MG', '', '', 'Tablet', 'TABLET', 10.79, 14.16, 24),
        ('UDILIV 150MG TABS', '', '', 'Tablet', 'TABLET', 26.77, 35.14, 80),
        ('UDILIV 300MG TAB', '', '', 'Tablet', 'TABLET', 49.27, 64.68, 60),
        ('ULTRACET', '', '', 'Tablet', 'TABLET', 15.02, 21.03, 20),
        ('ULTRACET  TAB', '', '', 'Tablet', 'TABLET', 15.02, 19.71, 5),
        ('ULTRAMED TAB', '', '', 'Tablet', 'TABLET', 8.52, 11.93, 76),
        ('URIBID TAB', '', '', 'Tablet', 'TABLET', 6.59, 8.65, 55),
        ('URO- BAG', '', '', 'Tablet', 'GENERAL', 18.0, 289.0, 4),
        ('URO METER', '', '', 'Tablet', 'GENERAL', 105.0, 520.0, 2),
        ('UROBAG  (ROMO-10)', '', '', 'Tablet', 'SURGICAL', 31.0, 289.0, 20),
        ('UROSMART PLUS', '', '', 'Tablet', 'TABLET', 24.48, 32.12, 118),
        ('VASOCON INJ 1ML', '', '', 'Injection', 'INJECTION', 10.91, 13.69, 15),
        ('VELTAM PLUS TABS', '', '', 'Tablet', 'TABLET', 27.29, 38.2, 15),
        ('VERICOSE AF XL', '', '', 'Tablet', 'SURGICAL', 1862.54, 2729.0, 1),
        ('VIBITE SR 100', '', '', 'Tablet', 'TABLET', 10.24, 13.53, 220),
        ('VILDANEX M', '', '', 'Tablet', 'TABLET', 6.83, 10.95, 180),
        ('VILDANEX M FORTE', '', '', 'Tablet', 'TABLET', 7.3, 12.09, 585),
        ('VILDARAY SR 100', '', '', 'Tablet', 'TABLET', 8.38, 13.45, 540),
        ('VITANGLE TAB', '', '', 'Tablet', 'TABLET', 8.8, 11.75, 64),
        ('VOAGE- MS 1000', '', '', 'Tablet', 'TABLET', 17.99, 23.61, 120),
        ('VOGLIBITE GM  1/0.2 TAB', '', '', 'Tablet', 'TABLET', 10.94, 14.35, 180),
        ('VOGLIBITE GM 1/0.3 TAB', '', '', 'Tablet', 'TABLET', 10.35, 13.58, 30),
        ('VOGLIBITE GM 2/0.2', '', '', 'Tablet', 'TABLET', 13.88, 18.22, 180),
        ('VOGLIBITE GM 2/0.3', '', '', 'Tablet', 'TABLET', 11.08, 14.53, 190),
        ('VOMIKIND - AMP', '', '', 'Injection', 'INJECTION', 9.68, 12.1, 19),
        ('VOMIKIND 4 MG TAB', '', '', 'Tablet', 'TABLET', 3.67, 4.81, 109),
        ('VONOGEN 20', '', '', 'Tablet', 'TABLET', 12.39, 17.35, 100),
        ('WALYTE 4.2GM POWDER', '', '', 'Powder', 'POWDER', 3.54, 4.64, 40),
        ('WALYTE ORS ORANGE', '', '', 'Powder', 'SACHETS', 3.74, 4.9, 9),
        ('WALYTE SACHETS', '', '', 'Powder', 'POWDER', 1.57, 2.06, 526),
        ('WATER AMP', '', '', 'Tablet', 'GENERAL', 2.1, 3.24, 184),
        ('WYSOLONE 5MG TABS', '', '', 'Tablet', 'TABLET', 0.59, 0.77, 35),
        ('WYSOLONE DT - 10MG', '', '', 'Tablet', 'TABLET', 1.04, 1.35, 30),
        ('WYSOLONE DT  5MG', '', '', 'Tablet', 'TABLET', 0.58, 0.76, 180),
        ('ZANOCIN 200MG TAB', '', '', 'Tablet', 'TABLET', 7.59, 10.61, 70),
        ('ZAVAMET 1000', '', '', 'Tablet', 'TABLET', 8.36, 11.7, 40),
        ('ZAVAMET 500 TAB', '', '', 'Tablet', 'TABLET', 9.6, 12.2, 300),
        ('ZENFLOX -OZ TAB', '', '', 'Tablet', 'TABLET', 11.23, 14.73, 50),
        ('ZEPOXIN 40 MG INJ', '', '', 'Injection', 'INJECTION', 13.0, 56.0, 16),
        ('ZESTOVIT 4G CAP', '', '', 'Tablet', 'TABLET', 14.78, 19.4, 95),
        ('ZETASEPTIC 100 ML SOLUTION', '', '', 'Syrup', 'INFUSION', 54.0, 99.98, 11),
        ('ZOFER  4MG TAB', '', '', 'Tablet', 'TABLET', 4.1, 5.75, 32),
        ('ZOLANGLE 40', '', '', 'Tablet', 'TABLET', 9.0, 12.0, 630),
        ('ZORYL 1MG TABS', '', '', 'Tablet', 'TABLET', 8.79, 12.3, 20),
        ('ZORYL 2MG TABS', '', '', 'Tablet', 'TABLET', 12.32, 17.25, 20),
        ('ZORYL M 0.5 TAB', '', '', 'Tablet', 'TABLET', 3.36, 4.41, 220),
        ('ZORYL M 1FORTE TAB', '', '', 'Tablet', 'TABLET', 9.89, 13.31, 120),
        ('ZORYL M-2 FORTE TAB', '', '', 'Tablet', 'TABLET', 12.86, 16.98, 165),
        ('ZYTEE GEL (TUBE)', '', '', 'Cream/Ointment', 'CREAM/OINT/GEL', 85.0, 111.56, 1),
    ]
    for name,company,comp,cat_name,grp,pp,sp,qty in medicines:
        cat_id = cat_map.get(cat_name,1)
        mid = db.execute("INSERT OR IGNORE INTO pharmacy (medicine_name,medicine_company,medicine_composition,medicine_category_id,medicine_group,unit,reorder_level) VALUES (?,?,?,?,?,?,?)",
            (name,company,comp,cat_id,grp,cat_name,20)).lastrowid
        if mid:
            expiry = (date.today() + timedelta(days=365)).isoformat()
            db.execute("INSERT INTO medicine_batch_details (pharmacy_id,batch_no,manufacture_date,expiry_date,purchase_price,sale_price,available_quantity) VALUES (?,?,?,?,?,?,?)",
                (mid,f'B{mid:04d}',today,expiry,pp,sp,qty))
    db.commit()

    # Bed types, floors, groups, beds
    bed_types = [('General Ward',200),('Semi-Private',400),('Private',800),('ICU',2000),('NICU',2500),('Emergency',500)]
    for bt,charge in bed_types:
        db.execute("INSERT OR IGNORE INTO bed_type (bed_type,charge_per_day) VALUES (?,?)", (bt,charge))
    floors = ['Ground Floor','First Floor','Second Floor','Third Floor']
    for f_ in floors:
        db.execute("INSERT OR IGNORE INTO floor (floor_name) VALUES (?)", (f_,))
    db.commit()
    fl_id = db.execute("SELECT id FROM floor LIMIT 1").fetchone()['id']
    db.execute("INSERT OR IGNORE INTO bed_group (bed_group,floor_id) VALUES ('Ward A',?)", (fl_id,))
    db.execute("INSERT OR IGNORE INTO bed_group (bed_group,floor_id) VALUES ('Ward B',?)", (fl_id,))
    db.commit()
    grp_id = db.execute("SELECT id FROM bed_group LIMIT 1").fetchone()['id']
    bt_id  = db.execute("SELECT id FROM bed_type LIMIT 1").fetchone()['id']
    for i in range(1,21):
        db.execute("INSERT OR IGNORE INTO bed (bed_name,bed_type_id,bed_group_id) VALUES (?,?,?)", (f'B{i:03d}',bt_id,grp_id))
    db.commit()

    # Sample patients
    import random
    names = [('Ravi','Kumar'),('Priya','Sharma'),('Ahmed','Khan'),('Susan','Miller'),
             ('Carlos','Lopez'),('Fatima','Ali'),('James','Wilson'),('Meera','Patel'),
             ('Robert','Brown'),('Aisha','Noor')]
    for i,(fn,ln) in enumerate(names,1):
        pid = f'PID{i:04d}'
        age = random.randint(18,75)
        db.execute("INSERT OR IGNORE INTO patients (patient_unique_id,patient_name,guardian_name,gender,age,blood_group,mobile,email,address,patient_type) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (pid,f'{fn} {ln}',f'Guardian of {fn}','Male' if i%2==0 else 'Female',age,
             random.choice(['A+','B+','O+','AB+','A-','O-']),
             f'+1-555-{i:04d}',f'{fn.lower()}.{ln.lower()}@email.com',
             f'{i} Main Street, City','OPD'))
    db.commit()

    # Leave types
    leave_types = [('Annual Leave',15,1,'Yearly annual leave'),('Sick Leave',12,0,'Medical sick leave'),
                   ('Casual Leave',7,0,'Casual/personal leave'),('Maternity Leave',90,0,'Maternity leave'),
                   ('Emergency Leave',3,0,'Emergency leave')]
    for name,days,cf,desc in leave_types:
        db.execute("INSERT OR IGNORE INTO leave_types (name,days_allowed,carry_forward,description) VALUES (?,?,?,?)", (name,days,cf,desc))

    # Income/expense heads
    for cat in ['OPD Charges','IPD Charges','Lab Charges','Pharmacy Sales','Ambulance','Consultation','Other Income']:
        db.execute("INSERT OR IGNORE INTO income_head (income_category) VALUES (?)", (cat,))
    for cat in ['Medicines Purchase','Salaries','Maintenance','Utilities','Equipment','Consumables','Other Expense']:
        db.execute("INSERT OR IGNORE INTO expense_head (exp_category) VALUES (?)", (cat,))

    # TPA
    db.execute("INSERT OR IGNORE INTO tpa (organisation_name,contact_person,email,phone,coverage_limit,is_active) VALUES ('Star Health Insurance','Mr. Rajan','rajan@starhealth.com','+91-9000000001',100000,1)")
    db.execute("INSERT OR IGNORE INTO tpa (organisation_name,contact_person,email,phone,coverage_limit,is_active) VALUES ('United Health Care','Ms. Priya','priya@uhc.com','+91-9000000002',200000,1)")

    # Vehicles
    db.execute("INSERT OR IGNORE INTO vehicle (vehicle_name,vehicle_number,vehicle_type,driver_name,driver_phone,status) VALUES ('Ambulance 1','AMB-001','ambulance','Raju Kumar','+1-555-9001','available')")
    db.execute("INSERT OR IGNORE INTO vehicle (vehicle_name,vehicle_number,vehicle_type,driver_name,driver_phone,status) VALUES ('Ambulance 2','AMB-002','ambulance','Sita Ram','+1-555-9002','available')")
    db.execute("INSERT OR IGNORE INTO vehicle (vehicle_name,vehicle_number,vehicle_type,driver_name,driver_phone,status) VALUES ('Staff Van','VAN-001','van','Mohan Das','+1-555-9003','available')")

    # Blood inventory
    for bg in ['A+','A-','B+','B-','AB+','AB-','O+','O-']:
        import random as rnd
        db.execute("INSERT OR IGNORE INTO blood_inventory (blood_group,units_available) VALUES (?,?)", (bg,rnd.randint(5,30)))

    # Training programs
    db.execute("INSERT OR IGNORE INTO training (title,category,trainer,start_date,end_date,duration_hours,location) VALUES ('Basic Life Support & CPR','Clinical','Dr. John Smith',?,?,8,'Seminar Hall')", (today,today))
    db.execute("INSERT OR IGNORE INTO training (title,category,trainer,start_date,end_date,duration_hours,location) VALUES ('Infection Control Protocol','Safety','Linda Brown',?,?,4,'Training Room')", (today,today))

    # Sample income/expenses for last 7 days
    ihead_id = db.execute("SELECT id FROM income_head LIMIT 1").fetchone()['id']
    ehead_id = db.execute("SELECT id FROM expense_head LIMIT 1").fetchone()['id']
    for i in range(7):
        d = (date.today() - timedelta(days=i)).isoformat()
        import random as rnd
        db.execute("INSERT INTO income (name,income_head_id,amount,date,invoice_no) VALUES (?,?,?,?,?)",
            ('OPD Collection',ihead_id,rnd.randint(2000,8000),d,f'INV-{i:04d}'))
        db.execute("INSERT INTO expenses (name,exp_head_id,amount,date,invoice_no) VALUES (?,?,?,?,?)",
            ('Daily Supplies',ehead_id,rnd.randint(500,2000),d,f'EXP-{i:04d}'))

    db.commit()
    print("[HMS v3] Seed data inserted.")

def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(SCHEMA)
    db.commit()
    seed_data(db)
    db.close()
    print("[HMS v3] Database initialized.")


# ─────────────────────────────────────────────
# LOGIN / LOGOUT
# ─────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'hospitaladmin' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username','').strip()
        pw    = hash_pw(request.form.get('password',''))
        user  = qdb("SELECT staff.*,roles.name as role_name,roles.id as role_id FROM staff LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id LEFT JOIN roles ON roles.id=staff_roles.role_id WHERE (staff.email=? OR staff.employee_id=?) AND staff.password=? AND staff.is_active=1",
                    (email,email,pw), one=True)
        if user:
            settings = {r['name']:r['value'] for r in qdb("SELECT name,value FROM sch_settings")}
            session['hospitaladmin'] = {
                'id': user['id'], 'username': user['name']+' '+user['surname'],
                'email': user['email'], 'roles': user['role_name'],
                'role_id': user['role_id'], 'employee_id': user['employee_id'],
                'currency_symbol': settings.get('currency_symbol','₹'),
                'school_name': settings.get('name','Hospital')
            }
            edb("INSERT INTO userlog (staff_id,action,ip_address) VALUES (?,?,?)", (user['id'],'login',request.remote_addr))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = get_user()
    if user:
        edb("INSERT INTO userlog (staff_id,action,ip_address) VALUES (?,?,?)", (user.get('id',0),'logout',request.remote_addr))
    session.pop('hospitaladmin', None)
    return redirect(url_for('login'))

# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    today = date.today().isoformat()
    stats = {
        'total_patients': qdb("SELECT COUNT(*) as c FROM patients WHERE is_active=1", one=True)['c'],
        'opd_today': qdb("SELECT COUNT(*) as c FROM opd_details WHERE date=?", (today,), one=True)['c'],
        'ipd_current': qdb("SELECT COUNT(*) as c FROM ipd_details WHERE discharged='no'", one=True)['c'],
        'beds_available': qdb("SELECT COUNT(*) as c FROM bed WHERE is_active='yes' AND id NOT IN (SELECT bed FROM ipd_details WHERE discharged='no' AND bed>0)", one=True)['c'],
        'staff_active': qdb("SELECT COUNT(*) as c FROM staff WHERE is_active=1", one=True)['c'],
        'medicines': qdb("SELECT COUNT(*) as c FROM pharmacy", one=True)['c'],
        'appointments_today': qdb("SELECT COUNT(*) as c FROM appointments WHERE appointment_date=?", (today,), one=True)['c'],
        'pending_leaves': qdb("SELECT COUNT(*) as c FROM leave_applications WHERE status='pending'", one=True)['c'],
        'total_income': qdb("SELECT COALESCE(SUM(amount),0) as s FROM income WHERE date=?", (today,), one=True)['s'],
        'total_expense': qdb("SELECT COALESCE(SUM(amount),0) as s FROM expenses WHERE date=?", (today,), one=True)['s'],
        'blood_units': qdb("SELECT COALESCE(SUM(units_available),0) as s FROM blood_inventory", one=True)['s'],
        'pending_lab': qdb("SELECT COUNT(*) as c FROM lab_reports WHERE status='pending'", one=True)['c'],
        'dispense_today': qdb("SELECT COUNT(*) as c FROM medicine_dispense WHERE dispense_date=?", (today,), one=True)['c'],
    }
    appointments_today = qdb("""SELECT appointments.*,patients.patient_name,
        staff.name||' '||staff.surname as doctor_name
        FROM appointments LEFT JOIN patients ON patients.id=appointments.patient_id
        LEFT JOIN staff ON staff.id=appointments.doctor_id
        WHERE appointment_date=? ORDER BY appointment_time""", (today,))
    pending_leaves = qdb("""SELECT leave_applications.*,staff.name,staff.surname,staff.employee_id,leave_types.name as leave_name
        FROM leave_applications JOIN staff ON staff.id=leave_applications.staff_id
        JOIN leave_types ON leave_types.id=leave_applications.leave_type_id
        WHERE leave_applications.status='pending' ORDER BY leave_applications.id DESC LIMIT 5""")
    expiry_alerts = qdb("""SELECT pharmacy.medicine_name,medicine_batch_details.expiry_date,medicine_batch_details.available_quantity
        FROM medicine_batch_details JOIN pharmacy ON pharmacy.id=medicine_batch_details.pharmacy_id
        WHERE medicine_batch_details.expiry_date<=? AND medicine_batch_details.available_quantity>0
        ORDER BY medicine_batch_details.expiry_date""", ((date.today()+timedelta(days=30)).isoformat(),))
    recent_patients = qdb("SELECT * FROM patients ORDER BY id DESC LIMIT 5")
    return render_template('dashboard.html', stats=stats, appointments_today=appointments_today,
                           pending_leaves=pending_leaves, expiry_alerts=expiry_alerts, recent_patients=recent_patients)

@app.route('/api/chart')
@login_required
def api_chart():
    labels, income_data, expense_data, opd_data = [], [], [], []
    for i in range(6,-1,-1):
        d = (date.today()-timedelta(days=i)).isoformat()
        labels.append(d[5:])
        income_data.append(qdb("SELECT COALESCE(SUM(amount),0) as s FROM income WHERE date=?", (d,), one=True)['s'])
        expense_data.append(qdb("SELECT COALESCE(SUM(amount),0) as s FROM expenses WHERE date=?", (d,), one=True)['s'])
        opd_data.append(qdb("SELECT COUNT(*) as c FROM opd_details WHERE date=?", (d,), one=True)['c'])
    return jsonify({'labels':labels,'income':income_data,'expense':expense_data,'opd':opd_data})

# ─────────────────────────────────────────────
# APPOINTMENTS
# ─────────────────────────────────────────────
@app.route('/appointments')
@perm_required('appointments','view')
def appointments():
    date_filter = request.args.get('date', date.today().isoformat())
    rows = qdb("""SELECT appointments.*,patients.patient_name,
        staff.name||' '||staff.surname as doctor_name,department.department_name
        FROM appointments LEFT JOIN patients ON patients.id=appointments.patient_id
        LEFT JOIN staff ON staff.id=appointments.doctor_id
        LEFT JOIN department ON department.id=appointments.department_id
        WHERE appointment_date=? ORDER BY appointment_time""", (date_filter,))
    return render_template('appointments/list.html', records=rows, date_filter=date_filter)

@app.route('/appointments/add', methods=['GET','POST'])
@perm_required('appointments','add')
def appointment_add():
    if request.method == 'POST':
        f = request.form
        aid = edb("INSERT INTO appointments (patient_id,doctor_id,appointment_date,appointment_time,department_id,type,priority,symptoms,note) VALUES (?,?,?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('doctor_id',0),f.get('appointment_date',date.today().isoformat()),
             f.get('appointment_time',''),f.get('department_id',0),f.get('type','OPD'),
             f.get('priority','normal'),f.get('symptoms',''),f.get('note','')))
        audit('create','appointments',aid,'New appointment added')
        flash('Appointment booked.','success')
        return redirect(url_for('appointments'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT staff.*,department.department_name FROM staff LEFT JOIN department ON department.id=staff.department WHERE staff.is_active=1 ORDER BY staff.name")
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    return render_template('appointments/add.html', patients=patients, doctors=doctors, departments=departments, today=date.today().isoformat())

@app.route('/appointments/<int:aid>/status', methods=['POST'])
@perm_required('appointments','edit')
def appointment_status(aid):
    edb("UPDATE appointments SET status=? WHERE id=?", (request.form.get('status','completed'),aid))
    flash('Status updated.','success')
    return redirect(url_for('appointments'))

# ─────────────────────────────────────────────
# PATIENTS
# ─────────────────────────────────────────────
@app.route('/patients')
@perm_required('patients','view')
def patients():
    search = request.args.get('q','')
    if search:
        rows = qdb("SELECT * FROM patients WHERE is_active=1 AND (patient_name LIKE ? OR patient_unique_id LIKE ? OR mobile LIKE ?) ORDER BY id DESC",
                   (f'%{search}%',f'%{search}%',f'%{search}%'))
    else:
        rows = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY id DESC")
    return render_template('patients/list.html', patients=rows, search=search)

@app.route('/patients/add', methods=['GET','POST'])
@perm_required('patients','add')
def patient_add():
    if request.method == 'POST':
        f = request.form
        # Auto-generate patient ID
        count = qdb("SELECT COUNT(*) as c FROM patients", one=True)['c']
        pid_str = f'PID{count+1:04d}'
        new_id = edb("INSERT INTO patients (patient_unique_id,patient_name,guardian_name,gender,dob,age,blood_group,mobile,email,address,patient_type,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid_str,f.get('patient_name'),f.get('guardian_name'),f.get('gender'),f.get('dob',''),
             f.get('age',0),f.get('blood_group'),f.get('mobile'),f.get('email'),f.get('address'),f.get('patient_type','OPD'),f.get('notes','')))
        audit('create','patients',new_id,f'Patient {f.get("patient_name")} added')
        flash(f'Patient added with ID: {pid_str}','success')
        return redirect(url_for('patient_view',pid=new_id))
    return render_template('patients/add.html')

@app.route('/patients/<int:pid>')
@perm_required('patients','view')
def patient_view(pid):
    p = qdb("SELECT * FROM patients WHERE id=?", (pid,), one=True)
    if not p: abort(404)
    opd_records = qdb("""SELECT opd_details.*,staff.name||' '||staff.surname as doctor_name,tpa.organisation_name as tpa_name
        FROM opd_details LEFT JOIN staff ON staff.id=opd_details.doctor_id
        LEFT JOIN tpa ON tpa.id=opd_details.tpa_id
        WHERE opd_details.patient_id=? ORDER BY opd_details.id DESC""", (pid,))
    ipd_records = qdb("""SELECT ipd_details.*,staff.name||' '||staff.surname as doctor_name,
        bed.bed_name FROM ipd_details LEFT JOIN staff ON staff.id=ipd_details.doctor_id
        LEFT JOIN bed ON bed.id=ipd_details.bed
        WHERE ipd_details.patient_id=? ORDER BY ipd_details.id DESC""", (pid,))
    lab_records = qdb("SELECT * FROM lab_reports WHERE patient_id=? ORDER BY id DESC", (pid,))
    appointments = qdb("""SELECT appointments.*,staff.name||' '||staff.surname as doctor_name
        FROM appointments LEFT JOIN staff ON staff.id=appointments.doctor_id
        WHERE appointments.patient_id=? ORDER BY appointments.id DESC""", (pid,))
    dispenses = qdb("""SELECT medicine_dispense.*,pharmacy.medicine_name,staff.name||' '||staff.surname as dispensed_by_name
        FROM medicine_dispense LEFT JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
        WHERE medicine_dispense.patient_id=? ORDER BY medicine_dispense.id DESC""", (pid,))
    blood_requests = qdb("SELECT * FROM blood_requests WHERE patient_id=? ORDER BY id DESC", (pid,))
    return render_template('patients/view.html', patient=dict(p), opd_records=opd_records,
                           ipd_records=ipd_records, lab_records=lab_records, appointments=appointments,
                           dispenses=dispenses, blood_requests=blood_requests)

@app.route('/patients/<int:pid>/edit', methods=['GET','POST'])
@perm_required('patients','edit')
def patient_edit(pid):
    p = qdb("SELECT * FROM patients WHERE id=?", (pid,), one=True)
    if not p: abort(404)
    if request.method == 'POST':
        f = request.form
        edb("UPDATE patients SET patient_name=?,guardian_name=?,gender=?,dob=?,age=?,blood_group=?,mobile=?,email=?,address=?,patient_type=?,notes=? WHERE id=?",
            (f.get('patient_name'),f.get('guardian_name'),f.get('gender'),f.get('dob'),f.get('age',0),
             f.get('blood_group'),f.get('mobile'),f.get('email'),f.get('address'),f.get('patient_type','OPD'),f.get('notes',''),pid))
        flash('Patient updated.','success')
        return redirect(url_for('patient_view',pid=pid))
    return render_template('patients/edit.html', patient=dict(p))

@app.route('/patients/<int:pid>/delete', methods=['POST'])
@perm_required('patients','delete')
def patient_delete(pid):
    edb("UPDATE patients SET is_active=0 WHERE id=?", (pid,))
    flash('Patient removed.','success')
    return redirect(url_for('patients'))

# ─────────────────────────────────────────────
# OPD
# ─────────────────────────────────────────────
@app.route('/opd')
@perm_required('opd','view')
def opd():
    rows = qdb("""SELECT opd_details.*,patients.patient_name,patients.patient_unique_id,
        staff.name||' '||staff.surname as doctor_name,tpa.organisation_name as tpa_name
        FROM opd_details LEFT JOIN patients ON patients.id=opd_details.patient_id
        LEFT JOIN staff ON staff.id=opd_details.doctor_id
        LEFT JOIN tpa ON tpa.id=opd_details.tpa_id
        ORDER BY opd_details.id DESC LIMIT 200""")
    return render_template('opd/list.html', records=rows)

@app.route('/opd/add', methods=['GET','POST'])
@perm_required('opd','add')
def opd_add():
    if request.method == 'POST':
        f = request.form
        oid = edb("INSERT INTO opd_details (patient_id,doctor_id,date,symptoms,diagnosis,charge,payment_status,tpa_id,follow_up_date,note) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('doctor_id',0),f.get('date',date.today().isoformat()),
             f.get('symptoms',''),f.get('diagnosis',''),f.get('charge',0),
             f.get('payment_status','unpaid'),f.get('tpa_id',0),f.get('follow_up_date',''),f.get('note','')))
        audit('create','opd',oid,'OPD visit added')
        flash('OPD record added.','success')
        return redirect(url_for('opd'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    tpa_list = qdb("SELECT * FROM tpa WHERE is_active=1 ORDER BY organisation_name")
    return render_template('opd/add.html', patients=patients, doctors=doctors, tpa_list=tpa_list, today=date.today().isoformat())

# ─────────────────────────────────────────────
# IPD
# ─────────────────────────────────────────────
@app.route('/ipd')
@perm_required('ipd','view')
def ipd():
    rows = qdb("""SELECT ipd_details.*,patients.patient_name,patients.patient_unique_id,
        staff.name||' '||staff.surname as doctor_name, bed.bed_name
        FROM ipd_details LEFT JOIN patients ON patients.id=ipd_details.patient_id
        LEFT JOIN staff ON staff.id=ipd_details.doctor_id
        LEFT JOIN bed ON bed.id=ipd_details.bed
        ORDER BY ipd_details.id DESC""")
    return render_template('ipd/list.html', records=rows)

@app.route('/ipd/add', methods=['GET','POST'])
@perm_required('ipd','add')
def ipd_add():
    if request.method == 'POST':
        f = request.form
        iid = edb("INSERT INTO ipd_details (patient_id,doctor_id,bed,date,charge,payment_status,tpa_id,note) VALUES (?,?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('doctor_id',0),f.get('bed_id',0),
             f.get('date',date.today().isoformat()),f.get('charge',0),
             f.get('payment_status','unpaid'),f.get('tpa_id',0),f.get('note','')))
        audit('create','ipd',iid,'IPD admission added')
        flash('Patient admitted.','success')
        return redirect(url_for('ipd'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    beds     = qdb("""SELECT bed.*,bed_type.bed_type,bed_type.charge_per_day FROM bed
        LEFT JOIN bed_type ON bed_type.id=bed.bed_type_id
        WHERE bed.is_active='yes' AND bed.id NOT IN (SELECT bed FROM ipd_details WHERE discharged='no' AND bed>0)
        ORDER BY bed.bed_name""")
    tpa_list = qdb("SELECT * FROM tpa WHERE is_active=1")
    return render_template('ipd/add.html', patients=patients, doctors=doctors, beds=beds, tpa_list=tpa_list, today=date.today().isoformat())

@app.route('/ipd/<int:iid>/discharge', methods=['POST'])
@perm_required('ipd','edit')
def ipd_discharge(iid):
    edb("UPDATE ipd_details SET discharged='yes',discharge_date=? WHERE id=?", (date.today().isoformat(),iid))
    flash('Patient discharged.','success')
    return redirect(url_for('ipd'))

# ─────────────────────────────────────────────
# BEDS
# ─────────────────────────────────────────────
@app.route('/beds')
@perm_required('beds','view')
def beds():
    rows = qdb("""SELECT bed.*,bed_type.bed_type,bed_type.charge_per_day,bed_group.bed_group,
        ipd_details.id as ipd_id, patients.patient_name, staff.name||' '||staff.surname as doctor_name,
        ipd_details.date as admission_date
        FROM bed LEFT JOIN bed_type ON bed_type.id=bed.bed_type_id
        LEFT JOIN bed_group ON bed_group.id=bed.bed_group_id
        LEFT JOIN ipd_details ON ipd_details.bed=bed.id AND ipd_details.discharged='no'
        LEFT JOIN patients ON patients.id=ipd_details.patient_id
        LEFT JOIN staff ON staff.id=ipd_details.doctor_id
        WHERE bed.is_active='yes' ORDER BY bed.bed_name""")
    total = len(rows)
    occupied = sum(1 for r in rows if r['ipd_id'])
    return render_template('beds/list.html', beds=rows, total=total, occupied=occupied, available=total-occupied)

@app.route('/beds/add', methods=['GET','POST'])
@perm_required('beds','add')
def beds_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO bed (bed_name,bed_type_id,bed_group_id) VALUES (?,?,?)",
            (f.get('bed_name'),f.get('bed_type_id',0),f.get('bed_group_id',0)))
        flash('Bed added.','success')
        return redirect(url_for('beds'))
    bed_types  = qdb("SELECT * FROM bed_type ORDER BY bed_type")
    bed_groups = qdb("SELECT bed_group.*,floor.floor_name FROM bed_group LEFT JOIN floor ON floor.id=bed_group.floor_id")
    return render_template('beds/add.html', bed_types=bed_types, bed_groups=bed_groups)

# ─────────────────────────────────────────────
# LABORATORY
# ─────────────────────────────────────────────
@app.route('/lab')
@perm_required('lab','view')
def lab():
    rows = qdb("""SELECT lab_reports.*,patients.patient_name,patients.patient_unique_id,
        staff.name||' '||staff.surname as doctor_name
        FROM lab_reports LEFT JOIN patients ON patients.id=lab_reports.patient_id
        LEFT JOIN staff ON staff.id=lab_reports.doctor_id
        ORDER BY lab_reports.id DESC""")
    return render_template('lab/list.html', records=rows)

@app.route('/lab/add', methods=['GET','POST'])
@perm_required('lab','add')
def lab_add():
    if request.method == 'POST':
        f = request.form
        lid = edb("INSERT INTO lab_reports (patient_id,test_name,doctor_id,test_date,normal_range,unit,note) VALUES (?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('test_name'),f.get('doctor_id',0),
             f.get('test_date',date.today().isoformat()),f.get('normal_range',''),f.get('unit',''),f.get('note','')))
        audit('create','lab',lid,'Lab test ordered')
        flash('Lab test ordered.','success')
        return redirect(url_for('lab'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    return render_template('lab/add.html', patients=patients, doctors=doctors, today=date.today().isoformat())

@app.route('/lab/<int:lid>/result', methods=['POST'])
@perm_required('lab','edit')
def lab_result(lid):
    edb("UPDATE lab_reports SET result=?,status='completed',note=? WHERE id=?",
        (request.form.get('result',''),request.form.get('note',''),lid))
    flash('Result updated.','success')
    return redirect(url_for('lab'))


# ─────────────────────────────────────────────
# PHARMACY — Full end-to-end
# ─────────────────────────────────────────────
@app.route('/pharmacy')
@perm_required('pharmacy','view')
def pharmacy_list():
    rows = qdb("""SELECT pharmacy.*,medicine_category.medicine_category,
        COALESCE((SELECT SUM(available_quantity) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id),0) as total_qty,
        (SELECT MIN(expiry_date) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id AND available_quantity>0) as nearest_expiry,
        (SELECT MIN(sale_price) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id AND available_quantity>0) as sale_price
        FROM pharmacy LEFT JOIN medicine_category ON medicine_category.id=pharmacy.medicine_category_id
        ORDER BY pharmacy.medicine_name""")
    today_plus30 = (date.today()+timedelta(days=30)).isoformat()
    return render_template('pharmacy/list.html', medicines=rows, today_plus30=today_plus30, today=date.today().isoformat())

@app.route('/pharmacy/add', methods=['GET','POST'])
@perm_required('pharmacy','add')
def pharmacy_add():
    if request.method == 'POST':
        f = request.form
        mid = edb("INSERT INTO pharmacy (medicine_name,medicine_company,medicine_composition,medicine_category_id,medicine_group,unit,reorder_level) VALUES (?,?,?,?,?,?,?)",
            (f.get('medicine_name'),f.get('medicine_company'),f.get('medicine_composition'),
             f.get('medicine_category_id',1),f.get('medicine_group'),f.get('unit','Tablet'),f.get('reorder_level',10)))
        if f.get('batch_no') or f.get('quantity'):
            edb("INSERT INTO medicine_batch_details (pharmacy_id,batch_no,manufacture_date,expiry_date,purchase_price,sale_price,available_quantity) VALUES (?,?,?,?,?,?,?)",
                (mid,f.get('batch_no',''),f.get('manufacture_date',''),f.get('expiry_date',''),
                 f.get('purchase_price',0),f.get('sale_price',0),f.get('quantity',0)))
        audit('create','pharmacy',mid,f'Medicine {f.get("medicine_name")} added')
        flash('Medicine added successfully.','success')
        return redirect(url_for('pharmacy_list'))
    categories = qdb("SELECT * FROM medicine_category ORDER BY medicine_category")
    return render_template('pharmacy/add.html', categories=categories, today=date.today().isoformat())

@app.route('/pharmacy/<int:mid>/edit', methods=['GET','POST'])
@perm_required('pharmacy','edit')
def pharmacy_edit(mid):
    med = qdb("SELECT * FROM pharmacy WHERE id=?", (mid,), one=True)
    if not med: abort(404)
    if request.method == 'POST':
        f = request.form
        edb("UPDATE pharmacy SET medicine_name=?,medicine_company=?,medicine_composition=?,medicine_category_id=?,medicine_group=?,unit=?,reorder_level=? WHERE id=?",
            (f.get('medicine_name'),f.get('medicine_company'),f.get('medicine_composition'),
             f.get('medicine_category_id',1),f.get('medicine_group'),f.get('unit','Tablet'),f.get('reorder_level',10),mid))
        flash('Medicine updated.','success')
        return redirect(url_for('pharmacy_list'))
    categories = qdb("SELECT * FROM medicine_category ORDER BY medicine_category")
    batches = qdb("SELECT * FROM medicine_batch_details WHERE pharmacy_id=? ORDER BY expiry_date", (mid,))
    return render_template('pharmacy/edit.html', med=dict(med), categories=categories, batches=batches)

@app.route('/pharmacy/<int:mid>/stock-in', methods=['GET','POST'])
@perm_required('pharmacy','add')
def pharmacy_stock_in(mid):
    med = qdb("SELECT * FROM pharmacy WHERE id=?", (mid,), one=True)
    if not med: abort(404)
    if request.method == 'POST':
        f = request.form
        qty = int(f.get('quantity',0))
        pp = float(f.get('purchase_price',0))
        sp = float(f.get('sale_price',0))
        total_cost = qty * pp
        # Add new batch
        batch_id = edb("INSERT INTO medicine_batch_details (pharmacy_id,batch_no,manufacture_date,expiry_date,purchase_price,sale_price,available_quantity) VALUES (?,?,?,?,?,?,?)",
            (mid,f.get('batch_no',''),f.get('manufacture_date',''),f.get('expiry_date',''),pp,sp,qty))
        # Record in purchase log
        edb("INSERT INTO medicine_purchase (pharmacy_id,supplier_name,invoice_no,purchase_date,batch_no,manufacture_date,expiry_date,purchase_price,sale_price,quantity,total_cost,note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (mid,f.get('supplier_name',''),f.get('invoice_no',''),f.get('purchase_date',date.today().isoformat()),
             f.get('batch_no',''),f.get('manufacture_date',''),f.get('expiry_date',''),pp,sp,qty,total_cost,f.get('note','')))
        audit('stock_in','pharmacy',mid,f'Stock added: {qty} units of {med["medicine_name"]}')
        flash(f'Stock added: {qty} units. Batch {f.get("batch_no","")}.','success')
        return redirect(url_for('pharmacy_list'))
    return render_template('pharmacy/stock_in.html', med=dict(med), today=date.today().isoformat())

@app.route('/pharmacy/dispense', methods=['GET','POST'])
@perm_required('pharmacy','add')
def pharmacy_dispense():
    """Dispense medicines to a patient"""
    if request.method == 'POST':
        f = request.form
        patient_id = int(f.get('patient_id',0) or 0)
        if not patient_id:
            flash('Please select a patient before dispensing.', 'danger')
            return redirect(url_for('pharmacy_dispense'))
        items = []
        # Parse multiple medicine items
        med_ids = request.form.getlist('medicine_id')
        batch_ids = request.form.getlist('batch_id')
        quantities = request.form.getlist('quantity')
        notes_list = request.form.getlist('item_note')
        total_bill = 0.0
        for i,mid_str in enumerate(med_ids):
            if not mid_str: continue
            mid = int(mid_str)
            batch_id = int(batch_ids[i]) if i < len(batch_ids) and batch_ids[i] else 0
            qty = int(quantities[i]) if i < len(quantities) and quantities[i] else 1
            # Get batch price
            batch = qdb("SELECT * FROM medicine_batch_details WHERE id=?", (batch_id,), one=True) if batch_id else None
            if not batch:
                batch = qdb("SELECT * FROM medicine_batch_details WHERE pharmacy_id=? AND available_quantity>=? ORDER BY expiry_date LIMIT 1", (mid,qty), one=True)
            if not batch:
                flash(f'Insufficient stock for one of the medicines.','danger')
                continue
            sp = float(batch['sale_price'])
            total = sp * qty
            total_bill += total
            # Deduct stock
            edb("UPDATE medicine_batch_details SET available_quantity=available_quantity-? WHERE id=?", (qty,batch['id']))
            # Record dispense
            did = edb("INSERT INTO medicine_dispense (patient_id,pharmacy_id,batch_id,quantity,sale_price,total_amount,dispense_date,dispensed_by,opd_id,ipd_id,note,payment_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (patient_id,mid,batch['id'],qty,sp,total,f.get('dispense_date',date.today().isoformat()),
                 get_user().get('id',0),f.get('opd_id',0),f.get('ipd_id',0),
                 notes_list[i] if i < len(notes_list) else '',f.get('payment_status','paid')))
            items.append(did)
        if items:
            audit('dispense','pharmacy',patient_id,f'Medicines dispensed to patient {patient_id}, total: {total_bill:.2f}')
            flash(f'Medicines dispensed successfully. Total: {get_user().get("currency_symbol","₹")}{total_bill:.2f}','success')
        return redirect(url_for('pharmacy_dispense'))
    patients_raw = qdb("SELECT id, patient_name, patient_unique_id, blood_group, mobile FROM patients WHERE is_active=1 ORDER BY patient_name")
    patients_list = [{'id': p['id'], 'patient_name': p['patient_name'] or '', 'patient_unique_id': p['patient_unique_id'] or '', 'blood_group': p['blood_group'] or '', 'mobile': p['mobile'] or ''} for p in patients_raw]
    medicines = qdb("""SELECT pharmacy.*,medicine_category.medicine_category,
        COALESCE((SELECT SUM(available_quantity) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id),0) as total_qty,
        (SELECT MIN(sale_price) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id AND available_quantity>0) as sale_price
        FROM pharmacy LEFT JOIN medicine_category ON medicine_category.id=pharmacy.medicine_category_id
        WHERE (SELECT SUM(available_quantity) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id)>0
        ORDER BY pharmacy.medicine_name""")
    medicines_list = [{'id': m['id'], 'medicine_name': m['medicine_name'] or '', 'medicine_category': m['medicine_category'] or '', 'total_qty': int(m['total_qty'] or 0), 'sale_price': float(m['sale_price'] or 0), 'unit': m['unit'] or ''} for m in medicines]
    return render_template('pharmacy/dispense.html', patients=patients_list, medicines=medicines_list, today=date.today().isoformat())

@app.route('/pharmacy/dispense/patient/<int:pid>')
@perm_required('pharmacy','view')
def pharmacy_patient_history(pid):
    """View dispensing history for a patient"""
    patient = qdb("SELECT * FROM patients WHERE id=?", (pid,), one=True)
    records = qdb("""SELECT medicine_dispense.*,pharmacy.medicine_name,pharmacy.unit,
        staff.name||' '||staff.surname as dispensed_by_name,
        medicine_batch_details.batch_no,medicine_batch_details.expiry_date
        FROM medicine_dispense LEFT JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
        LEFT JOIN medicine_batch_details ON medicine_batch_details.id=medicine_dispense.batch_id
        WHERE medicine_dispense.patient_id=? ORDER BY medicine_dispense.id DESC""", (pid,))
    return render_template('pharmacy/patient_history.html', patient=dict(patient) if patient else {}, records=records)

@app.route('/pharmacy/purchases')
@perm_required('pharmacy','view')
def pharmacy_purchases():
    rows = qdb("""SELECT medicine_purchase.*,pharmacy.medicine_name FROM medicine_purchase
        JOIN pharmacy ON pharmacy.id=medicine_purchase.pharmacy_id
        ORDER BY medicine_purchase.id DESC LIMIT 200""")
    return render_template('pharmacy/purchases.html', records=rows)


@app.route('/pharmacy/expiry')
@perm_required('pharmacy','view')
def pharmacy_expiry():
    """Show medicines expiring soon with search"""
    days = int(request.args.get('days', 90))
    search = request.args.get('search', '').strip()
    cutoff = (date.today() + timedelta(days=days)).isoformat()
    today_str = date.today().isoformat()
    
    base_query = """SELECT pharmacy.id, pharmacy.medicine_name, pharmacy.medicine_company,
        medicine_category.medicine_category,
        medicine_batch_details.id as batch_id,
        medicine_batch_details.batch_no,
        medicine_batch_details.expiry_date,
        medicine_batch_details.available_quantity,
        medicine_batch_details.sale_price,
        medicine_batch_details.purchase_price,
        CASE 
            WHEN medicine_batch_details.expiry_date < ? THEN 'expired'
            WHEN medicine_batch_details.expiry_date <= ? THEN 'critical'
            WHEN medicine_batch_details.expiry_date <= ? THEN 'warning'
            ELSE 'ok'
        END as status
        FROM medicine_batch_details
        JOIN pharmacy ON pharmacy.id = medicine_batch_details.pharmacy_id
        LEFT JOIN medicine_category ON medicine_category.id = pharmacy.medicine_category_id
        WHERE medicine_batch_details.expiry_date <= ?
        AND medicine_batch_details.available_quantity > 0"""
    
    params = [today_str,
              (date.today() + timedelta(days=30)).isoformat(),
              (date.today() + timedelta(days=60)).isoformat(),
              cutoff]
    
    if search:
        base_query += " AND (pharmacy.medicine_name LIKE ? OR medicine_category.medicine_category LIKE ?)"
        params += [f'%{search}%', f'%{search}%']
    
    base_query += " ORDER BY medicine_batch_details.expiry_date ASC"
    
    rows = qdb(base_query, params)
    
    expired_count = sum(1 for r in rows if r['status'] == 'expired')
    critical_count = sum(1 for r in rows if r['status'] == 'critical')
    warning_count = sum(1 for r in rows if r['status'] == 'warning')
    
    return render_template('pharmacy/expiry.html', 
                           medicines=rows, days=days, search=search,
                           today=today_str,
                           expired_count=expired_count,
                           critical_count=critical_count,
                           warning_count=warning_count)


@app.route('/pharmacy/walkin', methods=['GET','POST'])
@perm_required('pharmacy','add')
def pharmacy_walkin():
    """Dispense medicines to walk-in / outside patients - print bill"""
    if request.method == 'POST':
        f = request.form
        customer_name = f.get('customer_name','Walk-in Customer').strip() or 'Walk-in Customer'
        med_ids = request.form.getlist('medicine_id')
        batch_ids = request.form.getlist('batch_id')
        quantities = request.form.getlist('quantity')
        item_notes = request.form.getlist('item_note')
        total_bill = 0.0
        items_dispensed = []
        for i, mid_str in enumerate(med_ids):
            if not mid_str: continue
            mid = int(mid_str)
            batch_id = int(batch_ids[i]) if i < len(batch_ids) and batch_ids[i] else 0
            qty = int(quantities[i]) if i < len(quantities) and quantities[i] else 1
            batch = qdb("SELECT * FROM medicine_batch_details WHERE id=?", (batch_id,), one=True) if batch_id else None
            if not batch:
                batch = qdb("SELECT * FROM medicine_batch_details WHERE pharmacy_id=? AND available_quantity>=? ORDER BY expiry_date LIMIT 1", (mid, qty), one=True)
            if not batch:
                flash(f'Insufficient stock for medicine.', 'danger')
                continue
            sp = float(batch['sale_price'])
            total = sp * qty
            total_bill += total
            edb("UPDATE medicine_batch_details SET available_quantity=available_quantity-? WHERE id=?", (qty, batch['id']))
            med = qdb("SELECT medicine_name FROM pharmacy WHERE id=?", (mid,), one=True)
            note = item_notes[i] if i < len(item_notes) else ''
            items_dispensed.append({
                'medicine_name': med['medicine_name'] if med else '',
                'quantity': qty,
                'sale_price': sp,
                'total': total,
                'note': note
            })
            # Temporarily disable FK for walk-in (no patient record needed)
            db = get_db()
            db.execute("PRAGMA foreign_keys = OFF")
            db.execute(
                "INSERT INTO medicine_dispense (patient_id,pharmacy_id,batch_id,quantity,sale_price,total_amount,dispense_date,dispensed_by,opd_id,ipd_id,note,payment_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (None, mid, batch['id'], qty, sp, total, f.get('dispense_date', date.today().isoformat()),
                 get_user().get('id', 0), 0, 0, f'Walk-in: {customer_name}' + (f' | {note}' if note else ''), f.get('payment_status','paid'))
            )
            db.commit()
            db.execute("PRAGMA foreign_keys = ON")
        
        if items_dispensed:
            audit('walkin_dispense', 'pharmacy', 0, f'Walk-in sale to {customer_name}, total: {total_bill:.2f}')
            action = f.get('action', 'save_print')
            if action == 'save_print':
                return render_template('pharmacy/walkin_bill.html',
                                       customer_name=customer_name,
                                       items=items_dispensed,
                                       total_bill=total_bill,
                                       dispense_date=f.get('dispense_date', date.today().isoformat()),
                                       dispensed_by=get_user().get('username',''),
                                       auto_print=True)
            else:
                flash(f'Walk-in sale saved. Total: ₹{total_bill:.2f}', 'success')
                return redirect(url_for('pharmacy_walkin'))
        flash('No medicines dispensed.', 'warning')
        return redirect(url_for('pharmacy_walkin'))
    
    medicines = qdb("""SELECT pharmacy.*,medicine_category.medicine_category,
        COALESCE((SELECT SUM(available_quantity) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id),0) as total_qty,
        (SELECT MIN(sale_price) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id AND available_quantity>0) as sale_price
        FROM pharmacy LEFT JOIN medicine_category ON medicine_category.id=pharmacy.medicine_category_id
        WHERE (SELECT SUM(available_quantity) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id)>0
        ORDER BY pharmacy.medicine_name""")
    medicines_list = [{'id': int(m['id']), 'medicine_name': str(m['medicine_name'] or ''), 'medicine_category': str(m['medicine_category'] or ''), 'total_qty': int(m['total_qty'] or 0), 'sale_price': float(m['sale_price'] or 0), 'unit': str(m['unit'] or '')} for m in medicines]
    return render_template('pharmacy/walkin.html', medicines=medicines_list, today=date.today().isoformat())

@app.route('/pharmacy/dispense/all')
@perm_required('pharmacy','view')
def pharmacy_dispense_all():
    date_filter = request.args.get('date', date.today().isoformat())
    rows = qdb("""SELECT medicine_dispense.*,pharmacy.medicine_name,pharmacy.unit,
        COALESCE(patients.patient_name, 
            CASE WHEN medicine_dispense.note LIKE 'Walk-in: %' 
                 THEN SUBSTR(medicine_dispense.note, 10) 
                 ELSE 'Walk-in Customer' END
        ) as patient_name,
        COALESCE(patients.patient_unique_id, 
            CASE WHEN medicine_dispense.patient_id IS NULL THEN 'Walk-in' ELSE '' END
        ) as patient_unique_id,
        medicine_dispense.patient_id as pid,
        staff.name||' '||staff.surname as dispensed_by_name
        FROM medicine_dispense 
        LEFT JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        LEFT JOIN patients ON patients.id=medicine_dispense.patient_id
        LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
        WHERE medicine_dispense.dispense_date=? 
        ORDER BY medicine_dispense.id DESC""", (date_filter,))
    
    # Build bills grouped by patient + session
    bills = {}
    all_rows = []
    for r in rows:
        row_dict = dict(r)
        # Key: for walk-in use note, for patients use patient_id
        if row_dict['pid'] is None:
            # Walk-in - group by customer name from note
            note = row_dict.get('note','') or ''
            raw = note.replace('Walk-in: ','').strip() if note.startswith('Walk-in:') else 'Walk-in Customer'
            cname = raw.split(' | ')[0].strip()  # Only the customer name, not medicine instructions
            row_dict['patient_name'] = cname
            row_dict['patient_unique_id'] = 'Walk-in'
            key = f"walkin_{cname}_{row_dict['dispense_date']}"
        else:
            key = f"patient_{row_dict['pid']}_{row_dict['dispense_date']}"
        
        if key not in bills:
            bills[key] = {
                'patient_name': row_dict['patient_name'],
                'patient_unique_id': row_dict['patient_unique_id'],
                'patient_id': row_dict['pid'],
                'dispense_date': row_dict['dispense_date'],
                'dispensed_by_name': row_dict['dispensed_by_name'],
                'payment_status': row_dict['payment_status'],
                'is_walkin': row_dict['pid'] is None,
                'medicines': [],
                'bill_total': 0.0
            }
        bills[key]['medicines'].append(row_dict)
        bills[key]['bill_total'] += float(row_dict['total_amount'] or 0)
        all_rows.append(row_dict)
    
    total = sum(float(r['total_amount'] or 0) for r in all_rows)
    bills_list = list(bills.values())
    return render_template('pharmacy/dispense_all.html', 
                           records=all_rows, 
                           bills=bills_list,
                           date_filter=date_filter, 
                           total=total)


@app.route('/pharmacy/bill/print')
@perm_required('pharmacy','view')
def pharmacy_bill_print():
    """Print a specific patient's bill for a date"""
    patient_id = request.args.get('patient_id')
    customer = request.args.get('customer', '')
    disp_date = request.args.get('date', date.today().isoformat())
    
    if patient_id and patient_id != 'None':
        # Registered patient
        rows = qdb("""SELECT medicine_dispense.*, pharmacy.medicine_name, pharmacy.unit,
            patients.patient_name, patients.patient_unique_id, patients.mobile,
            staff.name||' '||staff.surname as dispensed_by_name
            FROM medicine_dispense
            LEFT JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
            LEFT JOIN patients ON patients.id=medicine_dispense.patient_id
            LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
            WHERE medicine_dispense.patient_id=? AND medicine_dispense.dispense_date=?
            ORDER BY medicine_dispense.id""", (int(patient_id), disp_date))
        items = [dict(r) for r in rows]
        pname = items[0]['patient_name'] if items else 'Patient'
        puid  = items[0]['patient_unique_id'] if items else ''
    else:
        # Walk-in
        rows = qdb("""SELECT medicine_dispense.*, pharmacy.medicine_name, pharmacy.unit,
            staff.name||' '||staff.surname as dispensed_by_name
            FROM medicine_dispense
            LEFT JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
            LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
            WHERE medicine_dispense.patient_id IS NULL 
              AND medicine_dispense.dispense_date=?
              AND medicine_dispense.note LIKE ?
            ORDER BY medicine_dispense.id""", (disp_date, f'Walk-in: {customer}%'))
        items = [dict(r) for r in rows]
        pname = customer or 'Walk-in Customer'
        puid  = 'Walk-in'
    
    total_bill = sum(float(r.get('total_amount') or 0) for r in items)
    dispensed_by = items[0].get('dispensed_by_name','') if items else ''
    
    return render_template('pharmacy/walkin_bill.html',
                           customer_name=pname,
                           items=[{
                               'medicine_name': r.get('medicine_name',''),
                               'quantity': r.get('quantity',1),
                               'sale_price': float(r.get('sale_price') or 0),
                               'total': float(r.get('total_amount') or 0),
                               'note': r.get('note','') if not (r.get('note','') or '').startswith('Walk-in:') else ''
                           } for r in items],
                           total_bill=total_bill,
                           dispense_date=disp_date,
                           dispensed_by=dispensed_by,
                           auto_print=True)

@app.route('/pharmacy/<int:mid>/batches')
@app.route('/api/pharmacy/<int:mid>/batches')
@perm_required('pharmacy','view')
def pharmacy_batches(mid):
    """Ajax: get available batches for a medicine"""
    batches = qdb("SELECT id, batch_no, manufacture_date, expiry_date, purchase_price, sale_price, available_quantity FROM medicine_batch_details WHERE pharmacy_id=? AND available_quantity>0 ORDER BY expiry_date", (mid,))
    batch_list = []
    for b in batches:
        batch_list.append({
            'id': b['id'],
            'batch_no': b['batch_no'] or '',
            'manufacture_date': b['manufacture_date'] or '',
            'expiry_date': b['expiry_date'] or '',
            'purchase_price': float(b['purchase_price'] or 0),
            'sale_price': float(b['sale_price'] or 0),
            'available_quantity': int(b['available_quantity'] or 0)
        })
    return jsonify(batch_list)

@app.route('/pharmacy/<int:mid>/delete', methods=['POST'])
@perm_required('pharmacy','delete')
def pharmacy_delete(mid):
    edb("DELETE FROM pharmacy WHERE id=?", (mid,))
    flash('Medicine deleted.','success')
    return redirect(url_for('pharmacy_list'))


# ─────────────────────────────────────────────
# STAFF & USER MANAGEMENT
# ─────────────────────────────────────────────
@app.route('/staff')
@perm_required('staff','view')
def staff_list():
    rows = qdb("""SELECT staff.*,roles.name as role_name,department.department_name,staff_designation.designation as designation_name
        FROM staff LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id
        LEFT JOIN roles ON roles.id=staff_roles.role_id
        LEFT JOIN department ON department.id=staff.department
        LEFT JOIN staff_designation ON staff_designation.id=staff.designation
        WHERE staff.is_active=1 ORDER BY staff.employee_id""")
    return render_template('staff/list.html', staff_list=rows)

@app.route('/staff/add', methods=['GET','POST'])
@perm_required('staff','add')
def staff_add():
    if request.method == 'POST':
        f = request.form
        # Generate employee ID
        count = qdb("SELECT COUNT(*) as c FROM staff", one=True)['c']
        emp_id = f'EMP{count+1:04d}'
        # Check if email exists
        existing = qdb("SELECT id FROM staff WHERE email=?", (f.get('email',''),), one=True)
        if existing:
            flash('Email already exists. Please use a different email.','danger')
            roles = qdb("SELECT * FROM roles WHERE is_active=1")
            departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
            designations = qdb("SELECT * FROM staff_designation ORDER BY designation")
            return render_template('staff/add.html', roles=roles, departments=departments, designations=designations)
        sid = edb("""INSERT INTO staff (employee_id,name,surname,email,password,phone,mobileno,gender,dob,blood_group,
            date_of_joining,address,department,designation,qualification,experience,basic_salary,bank_name,bank_account,emergency_contact,note)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (emp_id,f.get('name'),f.get('surname'),f.get('email'),hash_pw(f.get('password','admin123')),
             f.get('phone'),f.get('mobileno'),f.get('gender'),f.get('dob',''),f.get('blood_group',''),
             f.get('date_of_joining',date.today().isoformat()),f.get('address'),
             f.get('department',0),f.get('designation',0),f.get('qualification'),f.get('experience'),
             f.get('basic_salary',0),f.get('bank_name'),f.get('bank_account'),f.get('emergency_contact'),f.get('note','')))
        # Assign role
        role_id = f.get('role_id',0)
        if role_id:
            edb("INSERT OR REPLACE INTO staff_roles (staff_id,role_id) VALUES (?,?)", (sid,role_id))
        audit('create','staff',sid,f'Staff {f.get("name")} {f.get("surname")} created (Emp:{emp_id})')
        flash(f'Staff member created. Employee ID: {emp_id} | Login: {f.get("email")} | Password: {f.get("password","admin123")}','success')
        return redirect(url_for('staff_list'))
    roles = qdb("SELECT * FROM roles WHERE is_active=1 ORDER BY name")
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    designations = qdb("SELECT * FROM staff_designation ORDER BY designation")
    return render_template('staff/add.html', roles=roles, departments=departments, designations=designations, today=date.today().isoformat())

@app.route('/staff/<int:sid>/view')
@perm_required('staff','view')
def staff_view(sid):
    member = qdb("""SELECT staff.*,roles.name as role_name,department.department_name,staff_designation.designation as designation_name
        FROM staff LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id
        LEFT JOIN roles ON roles.id=staff_roles.role_id
        LEFT JOIN department ON department.id=staff.department
        LEFT JOIN staff_designation ON staff_designation.id=staff.designation
        WHERE staff.id=?""", (sid,), one=True)
    if not member: abort(404)
    attendance  = qdb("SELECT * FROM attendance WHERE staff_id=? ORDER BY date DESC LIMIT 30", (sid,))
    leaves      = qdb("SELECT leave_applications.*,leave_types.name as leave_name FROM leave_applications JOIN leave_types ON leave_types.id=leave_applications.leave_type_id WHERE staff_id=? ORDER BY id DESC", (sid,))
    appraisals  = qdb("SELECT * FROM performance_appraisal WHERE staff_id=? ORDER BY id DESC", (sid,))
    trainings   = qdb("SELECT training.*,training_participants.status as enroll_status,training_participants.score FROM training JOIN training_participants ON training_participants.training_id=training.id WHERE training_participants.staff_id=?", (sid,))
    payrolls    = qdb("SELECT * FROM payroll WHERE staff_id=? ORDER BY year DESC,id DESC LIMIT 12", (sid,))
    return render_template('staff/view.html', member=dict(member), attendance=attendance, leaves=leaves, appraisals=appraisals, trainings=trainings, payrolls=payrolls)

@app.route('/staff/<int:sid>/edit', methods=['GET','POST'])
@perm_required('staff','edit')
def staff_edit(sid):
    member = qdb("SELECT * FROM staff WHERE id=?", (sid,), one=True)
    if not member: abort(404)
    if request.method == 'POST':
        f = request.form
        edb("""UPDATE staff SET name=?,surname=?,email=?,phone=?,mobileno=?,gender=?,dob=?,
            date_of_joining=?,address=?,department=?,designation=?,qualification=?,experience=?,note=?,
            basic_salary=?,bank_name=?,bank_account=?,emergency_contact=?,blood_group=? WHERE id=?""",
            (f.get('name'),f.get('surname'),f.get('email'),f.get('phone'),f.get('mobileno'),
             f.get('gender'),f.get('dob'),f.get('date_of_joining'),f.get('address'),
             f.get('department',0),f.get('designation',0),f.get('qualification'),
             f.get('experience'),f.get('note'),f.get('basic_salary',0),f.get('bank_name'),
             f.get('bank_account'),f.get('emergency_contact'),f.get('blood_group'),sid))
        # Update role
        role_id = f.get('role_id')
        if role_id:
            edb("INSERT OR REPLACE INTO staff_roles (staff_id,role_id) VALUES (?,?)", (sid,int(role_id)))
        # Update password if provided
        new_pw = f.get('new_password','').strip()
        if new_pw:
            edb("UPDATE staff SET password=? WHERE id=?", (hash_pw(new_pw),sid))
            flash(f'Password updated.','info')
        audit('update','staff',sid,'Staff profile updated')
        flash('Staff updated.','success')
        return redirect(url_for('staff_list'))
    roles = qdb("SELECT * FROM roles WHERE is_active=1 ORDER BY name")
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    designations = qdb("SELECT * FROM staff_designation ORDER BY designation")
    current_role = qdb("SELECT role_id FROM staff_roles WHERE staff_id=?", (sid,), one=True)
    return render_template('staff/edit.html', member=dict(member), roles=roles, departments=departments, designations=designations, current_role_id=current_role['role_id'] if current_role else 0)

@app.route('/staff/<int:sid>/reset-password', methods=['POST'])
@perm_required('staff','edit')
def staff_reset_password(sid):
    new_pw = request.form.get('new_password','admin123')
    edb("UPDATE staff SET password=? WHERE id=?", (hash_pw(new_pw),sid))
    audit('reset_password','staff',sid,'Password reset')
    flash(f'Password reset to: {new_pw}','success')
    return redirect(url_for('staff_view',sid=sid))

@app.route('/staff/<int:sid>/delete', methods=['POST'])
@perm_required('staff','delete')
def staff_delete(sid):
    edb("UPDATE staff SET is_active=0 WHERE id=?", (sid,))
    flash('Staff deactivated.','success')
    return redirect(url_for('staff_list'))

# ─────────────────────────────────────────────
# PAYROLL
# ─────────────────────────────────────────────
@app.route('/payroll')
@perm_required('payroll','view')
def payroll_list():
    rows = qdb("SELECT payroll.*,staff.name,staff.surname,staff.employee_id FROM payroll JOIN staff ON staff.id=payroll.staff_id ORDER BY payroll.id DESC")
    return render_template('payroll/list.html', records=rows)

@app.route('/payroll/add', methods=['GET','POST'])
@perm_required('payroll','add')
def payroll_add():
    if request.method == 'POST':
        f = request.form
        basic = float(f.get('basic_salary',0)); allow = float(f.get('allowances',0)); deduct = float(f.get('deductions',0))
        net = basic + allow - deduct
        edb("INSERT INTO payroll (staff_id,month,year,basic_salary,allowances,deductions,net_salary,payment_status,note) VALUES (?,?,?,?,?,?,?,?,?)",
            (f.get('staff_id'),f.get('month'),f.get('year',date.today().year),basic,allow,deduct,net,f.get('payment_status','unpaid'),f.get('note','')))
        flash('Payroll record added.','success')
        return redirect(url_for('payroll_list'))
    staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    months = ['January','February','March','April','May','June','July','August','September','October','November','December']
    return render_template('payroll/add.html', staff=staff, months=months, current_year=date.today().year)

@app.route('/payroll/<int:pid>/mark_paid', methods=['POST'])
@perm_required('payroll','edit')
def payroll_mark_paid(pid):
    edb("UPDATE payroll SET payment_status='paid',payment_date=? WHERE id=?", (date.today().isoformat(),pid))
    flash('Marked as paid.','success')
    return redirect(url_for('payroll_list'))

# ─────────────────────────────────────────────
# HR — LEAVE
# ─────────────────────────────────────────────
@app.route('/hr/leave')
@perm_required('hr_leave','view')
def hr_leave():
    rows = qdb("""SELECT leave_applications.*,staff.name,staff.surname,staff.employee_id,leave_types.name as leave_name
        FROM leave_applications JOIN staff ON staff.id=leave_applications.staff_id
        JOIN leave_types ON leave_types.id=leave_applications.leave_type_id
        ORDER BY leave_applications.id DESC""")
    leave_types = qdb("SELECT * FROM leave_types WHERE is_active=1")
    return render_template('hr/leave.html', records=rows, leave_types=leave_types)

@app.route('/hr/leave/add', methods=['GET','POST'])
@perm_required('hr_leave','add')
def hr_leave_add():
    if request.method == 'POST':
        f = request.form
        from_d = date.fromisoformat(f.get('from_date',date.today().isoformat()))
        to_d   = date.fromisoformat(f.get('to_date',date.today().isoformat()))
        days   = (to_d - from_d).days + 1
        edb("INSERT INTO leave_applications (staff_id,leave_type_id,from_date,to_date,total_days,reason) VALUES (?,?,?,?,?,?)",
            (f.get('staff_id'),f.get('leave_type_id'),f.get('from_date'),f.get('to_date'),days,f.get('reason','')))
        flash('Leave application submitted.','success')
        return redirect(url_for('hr_leave'))
    staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    leave_types = qdb("SELECT * FROM leave_types WHERE is_active=1")
    return render_template('hr/leave_add.html', staff=staff, leave_types=leave_types, today=date.today().isoformat())

@app.route('/hr/leave/<int:lid>/approve', methods=['POST'])
@perm_required('hr_leave','edit')
def hr_leave_approve(lid):
    status = request.form.get('status','approved')
    edb("UPDATE leave_applications SET status=?,approved_by=?,approved_date=? WHERE id=?",
        (status, get_user().get('id',0), date.today().isoformat(), lid))
    flash(f'Leave {status}.','success')
    return redirect(url_for('hr_leave'))

# ─────────────────────────────────────────────
# HR — ATTENDANCE
# ─────────────────────────────────────────────
@app.route('/hr/attendance')
@perm_required('hr_attendance','view')
def hr_attendance():
    date_filter = request.args.get('date', date.today().isoformat())
    rows = qdb("SELECT attendance.*,staff.name,staff.surname,staff.employee_id FROM attendance JOIN staff ON staff.id=attendance.staff_id WHERE attendance.date=? ORDER BY staff.employee_id", (date_filter,))
    all_staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY employee_id")
    # Build dict of marked records
    marked = {r['staff_id']: dict(r) for r in rows}
    return render_template('hr/attendance.html', records=rows, all_staff=all_staff, date_filter=date_filter, marked=marked)

@app.route('/hr/attendance/mark', methods=['POST'])
@perm_required('hr_attendance','add')
def hr_attendance_mark():
    date_val = request.form.get('date', date.today().isoformat())
    staff_ids = request.form.getlist('staff_id')
    statuses  = request.form.getlist('status')
    for i,sid in enumerate(staff_ids):
        st = statuses[i] if i < len(statuses) else 'present'
        tin  = request.form.get(f'time_in_{sid}','09:00')
        tout = request.form.get(f'time_out_{sid}','17:00')
        edb("INSERT OR REPLACE INTO attendance (staff_id,date,status,time_in,time_out) VALUES (?,?,?,?,?)", (sid,date_val,st,tin,tout))
    flash('Attendance saved.','success')
    return redirect(url_for('hr_attendance',date=date_val))

@app.route('/hr/attendance/report')
@perm_required('hr_attendance','view')
def hr_attendance_report():
    month = request.args.get('month', date.today().strftime('%Y-%m'))
    rows = qdb("""SELECT staff.id,staff.employee_id,staff.name,staff.surname,
        SUM(CASE WHEN attendance.status='present' THEN 1 ELSE 0 END) as present_days,
        SUM(CASE WHEN attendance.status='absent' THEN 1 ELSE 0 END) as absent_days,
        SUM(CASE WHEN attendance.status='late' THEN 1 ELSE 0 END) as late_days,
        SUM(CASE WHEN attendance.status='half_day' THEN 1 ELSE 0 END) as half_days,
        COUNT(attendance.id) as total_marked
        FROM staff LEFT JOIN attendance ON attendance.staff_id=staff.id AND strftime('%Y-%m',attendance.date)=?
        WHERE staff.is_active=1 GROUP BY staff.id ORDER BY staff.employee_id""", (month,))
    return render_template('hr/attendance_report.html', records=rows, month=month)

# ─────────────────────────────────────────────
# HR — APPRAISAL
# ─────────────────────────────────────────────
@app.route('/hr/appraisal')
@perm_required('hr_appraisal','view')
def hr_appraisal():
    rows = qdb("""SELECT performance_appraisal.*,staff.name,staff.surname,staff.employee_id,
        s2.name||' '||s2.surname as reviewer_name
        FROM performance_appraisal JOIN staff ON staff.id=performance_appraisal.staff_id
        LEFT JOIN staff s2 ON s2.id=performance_appraisal.reviewer_id
        ORDER BY performance_appraisal.id DESC""")
    return render_template('hr/appraisal.html', records=rows)

@app.route('/hr/appraisal/add', methods=['GET','POST'])
@perm_required('hr_appraisal','add')
def hr_appraisal_add():
    if request.method == 'POST':
        f = request.form
        scores = [int(f.get(k,0)) for k in ['punctuality','teamwork','technical_skills','communication','patient_care']]
        overall = sum(scores)/5
        grade = 'A+' if overall>=90 else 'A' if overall>=80 else 'B' if overall>=70 else 'C' if overall>=60 else 'D'
        edb("""INSERT INTO performance_appraisal (staff_id,period,reviewer_id,punctuality,teamwork,technical_skills,communication,patient_care,overall_score,grade,strengths,improvements,goals,reviewer_comments,status,review_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (f.get('staff_id'),f.get('period'),get_user().get('id',0),*scores,overall,grade,
             f.get('strengths',''),f.get('improvements',''),f.get('goals',''),f.get('reviewer_comments',''),f.get('status','draft'),date.today().isoformat()))
        flash('Appraisal saved.','success')
        return redirect(url_for('hr_appraisal'))
    staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    periods = [f'Q{q} {y}' for y in [date.today().year, date.today().year-1] for q in [1,2,3,4]]
    periods += [f'Annual {y}' for y in [date.today().year, date.today().year-1]]
    return render_template('hr/appraisal_add.html', staff=staff, periods=periods)

# ─────────────────────────────────────────────
# HR — TRAINING
# ─────────────────────────────────────────────
@app.route('/hr/training')
@perm_required('hr_training','view')
def hr_training():
    rows = qdb("""SELECT training.*,COUNT(training_participants.id) as enrolled_count
        FROM training LEFT JOIN training_participants ON training_participants.training_id=training.id
        GROUP BY training.id ORDER BY training.id DESC""")
    return render_template('hr/training.html', records=rows)

@app.route('/hr/training/add', methods=['GET','POST'])
@perm_required('hr_training','add')
def hr_training_add():
    if request.method == 'POST':
        f = request.form
        tid = edb("INSERT INTO training (title,category,trainer,start_date,end_date,duration_hours,location,description) VALUES (?,?,?,?,?,?,?,?)",
            (f.get('title'),f.get('category'),f.get('trainer'),f.get('start_date'),f.get('end_date'),f.get('duration_hours',0),f.get('location'),f.get('description','')))
        for sid in request.form.getlist('participants'):
            edb("INSERT OR IGNORE INTO training_participants (training_id,staff_id) VALUES (?,?)", (tid,sid))
        flash('Training program created.','success')
        return redirect(url_for('hr_training'))
    staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    categories = ['Clinical','Safety','Administrative','Technical','Soft Skills','Compliance','Other']
    return render_template('hr/training_add.html', staff=staff, categories=categories, today=date.today().isoformat())

@app.route('/hr/training/<int:tid>')
@perm_required('hr_training','view')
def hr_training_view(tid):
    training = qdb("SELECT * FROM training WHERE id=?", (tid,), one=True)
    participants = qdb("""SELECT training_participants.*,staff.name,staff.surname,staff.employee_id
        FROM training_participants JOIN staff ON staff.id=training_participants.staff_id
        WHERE training_participants.training_id=?""", (tid,))
    return render_template('hr/training_view.html', training=dict(training) if training else {}, participants=participants)

@app.route('/hr/training/<int:tid>/complete/<int:sid>', methods=['POST'])
@perm_required('hr_training','edit')
def hr_training_complete(tid, sid):
    score = request.form.get('score',0)
    cert  = 1 if request.form.get('certificate') else 0
    edb("UPDATE training_participants SET status='completed',score=?,certificate_issued=?,completion_date=? WHERE training_id=? AND staff_id=?",
        (score,cert,date.today().isoformat(),tid,sid))
    flash('Training marked as completed.','success')
    return redirect(url_for('hr_training_view',tid=tid))


# ─────────────────────────────────────────────
# BLOOD BANK
# ─────────────────────────────────────────────
@app.route('/bloodbank')
@perm_required('bloodbank','view')
def bloodbank():
    inventory  = qdb("SELECT * FROM blood_inventory ORDER BY blood_group")
    donations  = qdb("SELECT * FROM blood_donations ORDER BY id DESC LIMIT 50")
    requests   = qdb("""SELECT blood_requests.*,patients.patient_name FROM blood_requests
        LEFT JOIN patients ON patients.id=blood_requests.patient_id ORDER BY blood_requests.id DESC LIMIT 50""")
    return render_template('bloodbank/index.html', inventory=inventory, donations=donations, requests=requests)

@app.route('/bloodbank/donate', methods=['GET','POST'])
@perm_required('bloodbank','add')
def bloodbank_donate():
    if request.method == 'POST':
        f = request.form
        bg = f.get('blood_group')
        units = int(f.get('units_donated',1))
        edb("INSERT INTO blood_donations (donor_name,blood_group,donor_contact,donor_age,donation_date,units_donated,expiry_date,note) VALUES (?,?,?,?,?,?,?,?)",
            (f.get('donor_name'),bg,f.get('donor_contact'),f.get('donor_age',0),f.get('donation_date'),units,f.get('expiry_date',''),f.get('note','')))
        edb("INSERT OR IGNORE INTO blood_inventory (blood_group,units_available) VALUES (?,0)", (bg,))
        edb("UPDATE blood_inventory SET units_available=units_available+?,last_updated=CURRENT_TIMESTAMP WHERE blood_group=?", (units,bg))
        flash('Donation recorded and inventory updated.','success')
        return redirect(url_for('bloodbank'))
    blood_groups = ['A+','A-','B+','B-','AB+','AB-','O+','O-']
    return render_template('bloodbank/donate.html', blood_groups=blood_groups, today=date.today().isoformat())

@app.route('/bloodbank/request', methods=['GET','POST'])
@perm_required('bloodbank','add')
def bloodbank_request():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO blood_requests (patient_id,blood_group,units_required,required_date,doctor_id,purpose,note) VALUES (?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('blood_group'),f.get('units_required',1),f.get('required_date',''),f.get('doctor_id',0),f.get('purpose',''),f.get('note','')))
        flash('Blood request submitted.','success')
        return redirect(url_for('bloodbank'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    inventory = {r['blood_group']:r['units_available'] for r in qdb("SELECT * FROM blood_inventory")}
    blood_groups = ['A+','A-','B+','B-','AB+','AB-','O+','O-']
    return render_template('bloodbank/request.html', patients=patients, doctors=doctors, inventory=inventory, blood_groups=blood_groups)

@app.route('/bloodbank/request/<int:rid>/approve', methods=['POST'])
@perm_required('bloodbank','edit')
def bloodbank_approve(rid):
    req = qdb("SELECT * FROM blood_requests WHERE id=?", (rid,), one=True)
    if req:
        inv = qdb("SELECT * FROM blood_inventory WHERE blood_group=?", (req['blood_group'],), one=True)
        if inv and inv['units_available'] >= req['units_required']:
            edb("UPDATE blood_requests SET status='approved' WHERE id=?", (rid,))
            edb("UPDATE blood_inventory SET units_available=units_available-?,last_updated=CURRENT_TIMESTAMP WHERE blood_group=?", (req['units_required'],req['blood_group']))
            flash('Request approved and inventory updated.','success')
        else:
            edb("UPDATE blood_requests SET status='approved' WHERE id=?", (rid,))
            flash('Request approved (insufficient stock — please arrange externally).','warning')
    return redirect(url_for('bloodbank'))

# ─────────────────────────────────────────────
# INSURANCE / TPA
# ─────────────────────────────────────────────
@app.route('/insurance')
@perm_required('insurance','view')
def insurance():
    tpa_list = qdb("SELECT * FROM tpa ORDER BY organisation_name")
    return render_template('insurance/list.html', tpa_list=tpa_list)

@app.route('/insurance/add', methods=['GET','POST'])
@perm_required('insurance','add')
def insurance_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO tpa (organisation_name,contact_person,email,phone,address,coverage_limit,policy_details) VALUES (?,?,?,?,?,?,?)",
            (f.get('organisation_name'),f.get('contact_person'),f.get('email'),f.get('phone'),f.get('address'),f.get('coverage_limit',0),f.get('policy_details','')))
        flash('TPA added.','success')
        return redirect(url_for('insurance'))
    return render_template('insurance/add.html')

@app.route('/insurance/<int:tid>/toggle', methods=['POST'])
@perm_required('insurance','edit')
def insurance_toggle(tid):
    tpa = qdb("SELECT is_active FROM tpa WHERE id=?", (tid,), one=True)
    if tpa:
        edb("UPDATE tpa SET is_active=? WHERE id=?", (0 if tpa['is_active'] else 1, tid))
    flash('Status updated.','success')
    return redirect(url_for('insurance'))

# ─────────────────────────────────────────────
# VEHICLE / AMBULANCE
# ─────────────────────────────────────────────
@app.route('/vehicle')
@perm_required('vehicle','view')
def vehicle_list():
    vehicles = qdb("SELECT * FROM vehicle ORDER BY vehicle_name")
    trips    = qdb("""SELECT vehicle_trips.*,vehicle.vehicle_name,patients.patient_name
        FROM vehicle_trips LEFT JOIN vehicle ON vehicle.id=vehicle_trips.vehicle_id
        LEFT JOIN patients ON patients.id=vehicle_trips.patient_id
        ORDER BY vehicle_trips.id DESC LIMIT 50""")
    return render_template('vehicle/list.html', vehicles=vehicles, trips=trips)

@app.route('/vehicle/add', methods=['GET','POST'])
@perm_required('vehicle','add')
def vehicle_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO vehicle (vehicle_name,vehicle_number,vehicle_type,driver_name,driver_phone,fuel_type) VALUES (?,?,?,?,?,?)",
            (f.get('vehicle_name'),f.get('vehicle_number'),f.get('vehicle_type','ambulance'),f.get('driver_name'),f.get('driver_phone'),f.get('fuel_type','Diesel')))
        flash('Vehicle added.','success')
        return redirect(url_for('vehicle_list'))
    return render_template('vehicle/add.html')

@app.route('/vehicle/trip', methods=['GET','POST'])
@perm_required('vehicle','add')
def vehicle_trip():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO vehicle_trips (vehicle_id,patient_id,trip_date,pickup_location,drop_location,distance_km,charge,note) VALUES (?,?,?,?,?,?,?,?)",
            (f.get('vehicle_id'),f.get('patient_id',0),f.get('trip_date',date.today().isoformat()),
             f.get('pickup_location'),f.get('drop_location'),f.get('distance_km',0),f.get('charge',0),f.get('note','')))
        flash('Trip logged.','success')
        return redirect(url_for('vehicle_list'))
    vehicles = qdb("SELECT * FROM vehicle ORDER BY vehicle_name")
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    return render_template('vehicle/trip.html', vehicles=vehicles, patients=patients, today=date.today().isoformat())

# ─────────────────────────────────────────────
# VISITORS
# ─────────────────────────────────────────────
@app.route('/visitors')
@perm_required('visitors','view')
def visitors_list():
    visitors = qdb("""SELECT visitors.*,patients.patient_name FROM visitors
        LEFT JOIN patients ON patients.id=visitors.patient_id
        ORDER BY visitors.id DESC LIMIT 100""")
    return render_template('visitors/list.html', visitors=visitors)

@app.route('/visitors/add', methods=['GET','POST'])
@perm_required('visitors','add')
def visitor_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO visitors (visitor_name,patient_id,purpose,visit_date,visit_time,note) VALUES (?,?,?,?,?,?)",
            (f.get('visitor_name'),f.get('patient_id',0),f.get('purpose'),f.get('visit_date'),f.get('visit_time',''),f.get('note','')))
        flash('Visitor registered.','success')
        return redirect(url_for('visitors_list'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    return render_template('visitors/add.html', patients=patients, today=date.today().isoformat())

# ─────────────────────────────────────────────
# INCOME
# ─────────────────────────────────────────────
@app.route('/income')
@perm_required('income','view')
def income_list():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    rows  = qdb("SELECT income.*,income_head.income_category FROM income LEFT JOIN income_head ON income_head.id=income.income_head_id WHERE income.date BETWEEN ? AND ? ORDER BY income.date DESC",(start,end))
    total = sum(float(r['amount'] or 0) for r in rows)
    heads = qdb("SELECT * FROM income_head")
    return render_template('income/list.html', records=rows, total=total, start=start, end=end, heads=heads)

@app.route('/income/add', methods=['GET','POST'])
@perm_required('income','add')
def income_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO income (name,income_head_id,invoice_no,amount,date,note) VALUES (?,?,?,?,?,?)",
            (f.get('name'),f.get('income_head_id',0),f.get('invoice_no'),f.get('amount',0),f.get('date'),f.get('note','')))
        flash('Income recorded.','success')
        return redirect(url_for('income_list'))
    heads = qdb("SELECT * FROM income_head")
    return render_template('income/add.html', heads=heads, today=date.today().isoformat())

@app.route('/income/<int:iid>/delete', methods=['POST'])
@perm_required('income','delete')
def income_delete(iid):
    edb("DELETE FROM income WHERE id=?", (iid,))
    flash('Income record deleted.','success')
    return redirect(url_for('income_list'))

# ─────────────────────────────────────────────
# EXPENSES
# ─────────────────────────────────────────────
@app.route('/expenses')
@perm_required('expenses','view')
def expenses_list():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    rows  = qdb("SELECT expenses.*,expense_head.exp_category FROM expenses LEFT JOIN expense_head ON expense_head.id=expenses.exp_head_id WHERE expenses.date BETWEEN ? AND ? ORDER BY expenses.date DESC",(start,end))
    total = sum(float(r['amount'] or 0) for r in rows)
    heads = qdb("SELECT * FROM expense_head")
    return render_template('expenses/list.html', records=rows, total=total, start=start, end=end, heads=heads)

@app.route('/expenses/add', methods=['GET','POST'])
@perm_required('expenses','add')
def expense_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO expenses (name,exp_head_id,invoice_no,amount,date,note) VALUES (?,?,?,?,?,?)",
            (f.get('name'),f.get('exp_head_id',0),f.get('invoice_no'),f.get('amount',0),f.get('date'),f.get('note','')))
        flash('Expense recorded.','success')
        return redirect(url_for('expenses_list'))
    heads = qdb("SELECT * FROM expense_head")
    return render_template('expenses/add.html', heads=heads, today=date.today().isoformat())

@app.route('/expenses/<int:eid>/delete', methods=['POST'])
@perm_required('expenses','delete')
def expense_delete(eid):
    edb("DELETE FROM expenses WHERE id=?", (eid,))
    flash('Expense record deleted.','success')
    return redirect(url_for('expenses_list'))

# ─────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────
@app.route('/reports')
@perm_required('reports','view')
def reports():
    return render_template('reports/index.html')

@app.route('/reports/financial')
@perm_required('reports','view')
def report_financial():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    total_income  = qdb("SELECT COALESCE(SUM(amount),0) as s FROM income WHERE date BETWEEN ? AND ?",(start,end),one=True)['s']
    total_expense = qdb("SELECT COALESCE(SUM(amount),0) as s FROM expenses WHERE date BETWEEN ? AND ?",(start,end),one=True)['s']
    income_by_head  = qdb("SELECT income_head.income_category,COALESCE(SUM(income.amount),0) as total FROM income_head LEFT JOIN income ON income.income_head_id=income_head.id AND income.date BETWEEN ? AND ? GROUP BY income_head.id",(start,end))
    expense_by_head = qdb("SELECT expense_head.exp_category,COALESCE(SUM(expenses.amount),0) as total FROM expense_head LEFT JOIN expenses ON expenses.exp_head_id=expense_head.id AND expenses.date BETWEEN ? AND ? GROUP BY expense_head.id",(start,end))
    return render_template('reports/financial.html', total_income=total_income, total_expense=total_expense,
                           profit=total_income-total_expense, income_by_head=income_by_head,
                           expense_by_head=expense_by_head, start=start, end=end)

@app.route('/reports/patients')
@perm_required('reports','view')
def report_patients():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    opd = qdb("""SELECT opd_details.*,patients.patient_name,patients.gender,staff.name||' '||staff.surname as doctor_name
        FROM opd_details JOIN patients ON patients.id=opd_details.patient_id
        LEFT JOIN staff ON staff.id=opd_details.doctor_id
        WHERE opd_details.date BETWEEN ? AND ? ORDER BY opd_details.date DESC""",(start,end))
    ipd = qdb("""SELECT ipd_details.*,patients.patient_name,patients.gender,staff.name||' '||staff.surname as doctor_name,bed.bed_name
        FROM ipd_details JOIN patients ON patients.id=ipd_details.patient_id
        LEFT JOIN staff ON staff.id=ipd_details.doctor_id LEFT JOIN bed ON bed.id=ipd_details.bed
        WHERE ipd_details.date BETWEEN ? AND ? ORDER BY ipd_details.date DESC""",(start,end))
    return render_template('reports/patients.html', opd=opd, ipd=ipd, start=start, end=end)

@app.route('/reports/hr')
@perm_required('reports','view')
def report_hr():
    month = request.args.get('month', date.today().strftime('%Y-%m'))
    payroll_summary = qdb("SELECT COUNT(*) as count,SUM(net_salary) as total_payroll,SUM(CASE WHEN payment_status='paid' THEN 1 ELSE 0 END) as paid_count FROM payroll WHERE month=? AND year=?",
                          (datetime.strptime(month,'%Y-%m').strftime('%B'),int(month[:4])), one=True)
    leave_summary = qdb("""SELECT leave_types.name,COUNT(leave_applications.id) as count,
        SUM(CASE WHEN leave_applications.status='approved' THEN 1 ELSE 0 END) as approved,
        SUM(leave_applications.total_days) as total_days
        FROM leave_types LEFT JOIN leave_applications ON leave_applications.leave_type_id=leave_types.id
        GROUP BY leave_types.id""")
    dept_attendance = qdb("""SELECT department.department_name,
        SUM(CASE WHEN attendance.status='present' THEN 1 ELSE 0 END) as present,
        SUM(CASE WHEN attendance.status='absent' THEN 1 ELSE 0 END) as absent
        FROM department LEFT JOIN staff ON staff.department=department.id
        LEFT JOIN attendance ON attendance.staff_id=staff.id AND strftime('%Y-%m',attendance.date)=?
        WHERE staff.is_active=1 GROUP BY department.id ORDER BY department.department_name""",(month,))
    return render_template('reports/hr.html', payroll_summary=payroll_summary, leave_summary=leave_summary, dept_attendance=dept_attendance, month=month)

@app.route('/reports/pharmacy')
@perm_required('reports','view')
def report_pharmacy():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    dispenses = qdb("""SELECT medicine_dispense.*,pharmacy.medicine_name,patients.patient_name,
        staff.name||' '||staff.surname as dispensed_by_name
        FROM medicine_dispense JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        JOIN patients ON patients.id=medicine_dispense.patient_id
        LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
        WHERE medicine_dispense.dispense_date BETWEEN ? AND ? ORDER BY medicine_dispense.id DESC""",(start,end))
    total_revenue = sum(float(r['total_amount'] or 0) for r in dispenses)
    top_medicines = qdb("""SELECT pharmacy.medicine_name,SUM(medicine_dispense.quantity) as total_qty,
        SUM(medicine_dispense.total_amount) as total_revenue
        FROM medicine_dispense JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        WHERE medicine_dispense.dispense_date BETWEEN ? AND ?
        GROUP BY medicine_dispense.pharmacy_id ORDER BY total_revenue DESC LIMIT 10""",(start,end))
    return render_template('reports/pharmacy.html', dispenses=dispenses, total_revenue=total_revenue, top_medicines=top_medicines, start=start, end=end)


# ─────────────────────────────────────────────
# ADMIN PANEL — Full user & role management
# ─────────────────────────────────────────────
@app.route('/admin')
@perm_required('admin','view')
def admin():
    stats = {
        'total_users': qdb("SELECT COUNT(*) as c FROM staff WHERE is_active=1", one=True)['c'],
        'total_roles':  qdb("SELECT COUNT(*) as c FROM roles", one=True)['c'],
        'today_logins': qdb("SELECT COUNT(*) as c FROM userlog WHERE action='login' AND date(created_at)=?", (date.today().isoformat(),), one=True)['c'],
        'total_actions': qdb("SELECT COUNT(*) as c FROM audit_log", one=True)['c'],
    }
    roles = qdb("SELECT roles.*,COUNT(staff_roles.staff_id) as staff_count FROM roles LEFT JOIN staff_roles ON staff_roles.role_id=roles.id GROUP BY roles.id")
    user_logs = qdb("SELECT userlog.*,staff.name,staff.surname,roles.name as role FROM userlog LEFT JOIN staff ON staff.id=userlog.staff_id LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id LEFT JOIN roles ON roles.id=staff_roles.role_id ORDER BY userlog.id DESC LIMIT 20")
    recent_logs = qdb("SELECT * FROM audit_log ORDER BY id DESC LIMIT 15")
    return render_template('admin/panel.html', stats=stats, roles=roles, user_logs=user_logs, recent_logs=recent_logs)

@app.route('/admin/roles')
@perm_required('admin','view')
def admin_roles():
    roles = qdb("SELECT roles.*,COUNT(staff_roles.staff_id) as staff_count FROM roles LEFT JOIN staff_roles ON staff_roles.role_id=roles.id GROUP BY roles.id ORDER BY roles.id")
    return render_template('admin/roles.html', roles=roles)

@app.route('/admin/roles/add', methods=['GET','POST'])
@perm_required('admin','add')
def admin_role_add():
    if request.method == 'POST':
        f = request.form
        rid = edb("INSERT INTO roles (name,description) VALUES (?,?)", (f.get('name'),f.get('description','')))
        for mod in ALL_MODULES:
            v=1 if f.get(f'{mod}_view') else 0; a=1 if f.get(f'{mod}_add') else 0
            e=1 if f.get(f'{mod}_edit') else 0; d=1 if f.get(f'{mod}_delete') else 0
            edb("INSERT OR REPLACE INTO role_permissions (role_id,module,can_view,can_add,can_edit,can_delete) VALUES (?,?,?,?,?,?)",(rid,mod,v,a,e,d))
        audit('create','admin',rid,f'Role {f.get("name")} created')
        flash('Role created.','success')
        return redirect(url_for('admin_roles'))
    return render_template('admin/role_add.html', modules=ALL_MODULES)

@app.route('/admin/roles/<int:rid>/permissions', methods=['GET','POST'])
@perm_required('admin','edit')
def admin_role_permissions(rid):
    role = qdb("SELECT * FROM roles WHERE id=?", (rid,), one=True)
    if not role: abort(404)
    if request.method == 'POST':
        for mod in ALL_MODULES:
            v=1 if request.form.get(f'{mod}_view') else 0; a=1 if request.form.get(f'{mod}_add') else 0
            e=1 if request.form.get(f'{mod}_edit') else 0; d=1 if request.form.get(f'{mod}_delete') else 0
            edb("INSERT OR REPLACE INTO role_permissions (role_id,module,can_view,can_add,can_edit,can_delete) VALUES (?,?,?,?,?,?)",(rid,mod,v,a,e,d))
        audit('update','admin',rid,f'Permissions updated for role {role["name"]}')
        flash('Permissions saved.','success')
        return redirect(url_for('admin_roles'))
    rows = qdb("SELECT * FROM role_permissions WHERE role_id=?", (rid,))
    perms = {r['module']: {'view':bool(r['can_view']),'add':bool(r['can_add']),'edit':bool(r['can_edit']),'delete':bool(r['can_delete'])} for r in rows}
    return render_template('admin/role_permissions.html', role=dict(role), perms=perms, modules=ALL_MODULES)

@app.route('/admin/users')
@perm_required('admin','view')
def admin_users():
    users = qdb("""SELECT staff.*,roles.name as role_name,department.department_name
        FROM staff LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id
        LEFT JOIN roles ON roles.id=staff_roles.role_id
        LEFT JOIN department ON department.id=staff.department
        ORDER BY staff.employee_id""")
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/create', methods=['GET','POST'])
@perm_required('admin','add')
def admin_user_create():
    """Create a new user with role and module access"""
    if request.method == 'POST':
        f = request.form
        # Check email unique
        existing = qdb("SELECT id FROM staff WHERE email=?", (f.get('email',''),), one=True)
        if existing:
            flash('Email already in use.','danger')
            roles = qdb("SELECT * FROM roles WHERE is_active=1 ORDER BY name")
            departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
            return render_template('admin/user_create.html', roles=roles, departments=departments)
        count = qdb("SELECT COUNT(*) as c FROM staff", one=True)['c']
        emp_id = f.get('employee_id','').strip() or f'EMP{count+1:04d}'
        pw_raw = f.get('password','admin@123')
        sid = edb("""INSERT INTO staff (employee_id,name,surname,email,password,phone,gender,date_of_joining,department,basic_salary,is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?,1)""",
            (emp_id,f.get('name'),f.get('surname',''),f.get('email'),hash_pw(pw_raw),
             f.get('phone',''),f.get('gender',''),date.today().isoformat(),f.get('department',0),f.get('basic_salary',0)))
        role_id = int(f.get('role_id',1))
        edb("INSERT OR REPLACE INTO staff_roles (staff_id,role_id) VALUES (?,?)", (sid,role_id))
        # If custom permissions selected
        if f.get('custom_permissions'):
            for mod in ALL_MODULES:
                v=1 if f.get(f'{mod}_view') else 0; a=1 if f.get(f'{mod}_add') else 0
                e=1 if f.get(f'{mod}_edit') else 0; d=1 if f.get(f'{mod}_delete') else 0
                edb("INSERT OR REPLACE INTO role_permissions (role_id,module,can_view,can_add,can_edit,can_delete) VALUES (?,?,?,?,?,?)",
                    (role_id,mod,v,a,e,d))
        audit('create','admin',sid,f'User {f.get("name")} created with role {role_id}')
        flash(f'User created! Emp ID: {emp_id} | Email: {f.get("email")} | Password: {pw_raw}','success')
        return redirect(url_for('admin_users'))
    roles = qdb("SELECT * FROM roles WHERE is_active=1 ORDER BY name")
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    role_perms = {}
    for r in roles:
        rows = qdb("SELECT * FROM role_permissions WHERE role_id=?", (r['id'],))
        role_perms[r['id']] = {rw['module']: {'view':bool(rw['can_view']),'add':bool(rw['can_add']),'edit':bool(rw['can_edit']),'delete':bool(rw['can_delete'])} for rw in rows}
    return render_template('admin/user_create.html', roles=roles, departments=departments, modules=ALL_MODULES, role_perms_json=json.dumps(role_perms), today=date.today().isoformat())

@app.route('/admin/users/<int:uid>/toggle', methods=['POST'])
@perm_required('admin','edit')
def admin_user_toggle(uid):
    user = qdb("SELECT is_active FROM staff WHERE id=?", (uid,), one=True)
    if user:
        edb("UPDATE staff SET is_active=? WHERE id=?", (0 if user['is_active'] else 1, uid))
    flash('User status updated.','success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:uid>/reset_password', methods=['POST'])
@perm_required('admin','edit')
def admin_user_reset(uid):
    new_pw = request.form.get('new_password','admin@123')
    edb("UPDATE staff SET password=? WHERE id=?", (hash_pw(new_pw),uid))
    audit('reset_password','admin',uid,'Password reset by admin')
    flash(f'Password reset to: {new_pw}','success')
    return redirect(url_for('admin_users'))

@app.route('/admin/audit_log')
@perm_required('admin','view')
def admin_audit_log():
    page = int(request.args.get('page',1)); per_page = 50
    total = qdb("SELECT COUNT(*) as c FROM audit_log", one=True)['c']
    logs  = qdb("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (per_page,(page-1)*per_page))
    return render_template('admin/audit_log.html', logs=logs, page=page, per_page=per_page, total=total)

@app.route('/admin/settings', methods=['GET','POST'])
@perm_required('admin','edit')
def admin_settings():
    if request.method == 'POST':
        for key in ['name','email','phone','address','currency','currency_symbol','timezone','date_format','time_format','theme']:
            edb("INSERT OR REPLACE INTO sch_settings (name,value) VALUES (?,?)", (key, request.form.get(key,'')))
        # Update session currency symbol
        user = get_user()
        if user:
            user['currency_symbol'] = request.form.get('currency_symbol','₹')
            user['school_name'] = request.form.get('name','Hospital')
            session['hospitaladmin'] = user
        flash('Settings saved.','success')
        return redirect(url_for('admin_settings'))
    settings = {r['name']:r['value'] for r in qdb("SELECT name,value FROM sch_settings")}
    return render_template('admin/settings.html', settings=settings)

@app.route('/admin/departments', methods=['GET','POST'])
@perm_required('admin','add')
def admin_departments():
    if request.method == 'POST':
        action = request.form.get('action','add')
        if action == 'add':
            edb("INSERT INTO department (department_name,description) VALUES (?,?)", (request.form.get('department_name'),request.form.get('description','')))
            flash('Department added.','success')
        elif action == 'delete':
            edb("UPDATE department SET is_active=0 WHERE id=?", (request.form.get('dept_id'),))
            flash('Department removed.','success')
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    return render_template('admin/departments.html', departments=departments)

# ─────────────────────────────────────────────
# APP ENTRY
# ─────────────────────────────────────────────
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    else:
        # Run schema updates on existing db
        with app.app_context():
            db = get_db()
            db.executescript(SCHEMA)
            db.commit()
    app.run(debug=True, host='0.0.0.0', port=5000)

# ─────────────────────────────────────────────
# JINJA FILTERS
# ─────────────────────────────────────────────
import json as _json
@app.template_filter('fromjson')
def fromjson_filter(s):
    try: return _json.loads(s)
    except: return {}
