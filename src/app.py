from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_required, current_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db, User, Student, Course, Enrollment, Grade, Attendance, AuditLog
from logger import setup_logger
from auth.login import handle_login, handle_register, handle_2fa
from students import students_bp
from datetime import datetime
import bleach
import os


logger = setup_logger()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ict932-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secureapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True


db.init_app(app)
app.register_blueprint(students_bp)


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ── Audit Log Helper ──────────────────────────────────────────────────────────
def log_action(action):
    try:
        log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except:
        pass


# ── Security Headers ──────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    return handle_login()


@app.route('/register', methods=['GET', 'POST'])
def register():
    return handle_register()


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    return handle_2fa()


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)


@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        logger.warning(f"Unauthorized admin access by username: {current_user.username}")
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/logout')
@login_required
def logout():
    logger.info(f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for('login'))


# ── Student Routes ────────────────────────────────────────────────────────────
@app.route('/students')
@login_required
def students():
    if current_user.role not in ['admin', 'teacher']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    all_students = Student.query.all()
    log_action('Viewed students list')
    return render_template('students.html', students=all_students)


@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        student_id = bleach.clean(request.form.get('student_id'))
        full_name  = bleach.clean(request.form.get('full_name'))
        email      = bleach.clean(request.form.get('email'))
        phone      = bleach.clean(request.form.get('phone', ''))
        if Student.query.filter_by(student_id=student_id).first():
            flash('Student ID already exists.', 'danger')
            return redirect(url_for('add_student'))
        student = Student(student_id=student_id, full_name=full_name,
                          email=email, phone=phone)
        db.session.add(student)
        db.session.commit()
        log_action(f'Added student {student_id}')
        flash('Student added successfully!', 'success')
        return redirect(url_for('students'))
    return render_template('add_student.html')


# ── Course Routes ─────────────────────────────────────────────────────────────
@app.route('/courses')
@login_required
def courses():
    all_courses = Course.query.all()
    log_action('Viewed courses list')
    return render_template('courses.html', courses=all_courses)


@app.route('/courses/add', methods=['GET', 'POST'])
@login_required
def add_course():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        code = bleach.clean(request.form.get('course_code'))
        name = bleach.clean(request.form.get('course_name'))
        desc = bleach.clean(request.form.get('description', ''))
        if Course.query.filter_by(course_code=code).first():
            flash('Course code already exists.', 'danger')
            return redirect(url_for('add_course'))
        course = Course(course_code=code, course_name=name, description=desc)
        db.session.add(course)
        db.session.commit()
        log_action(f'Added course {code}')
        flash('Course added successfully!', 'success')
        return redirect(url_for('courses'))
    return render_template('add_course.html')


# ── Enrollment Route ──────────────────────────────────────────────────────────
@app.route('/enroll', methods=['GET', 'POST'])
@login_required
def enroll():
    if current_user.role not in ['admin', 'teacher']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    all_students = Student.query.all()
    all_courses  = Course.query.all()
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id  = request.form.get('course_id')
        existing = Enrollment.query.filter_by(
            student_id=student_id, course_id=course_id).first()
        if existing:
            flash('Student already enrolled in this course.', 'warning')
        else:
            enrollment = Enrollment(student_id=student_id, course_id=course_id)
            db.session.add(enrollment)
            db.session.commit()
            log_action(f'Enrolled student {student_id} in course {course_id}')
            flash('Student enrolled successfully!', 'success')
        return redirect(url_for('enroll'))
    return render_template('enroll.html', students=all_students, courses=all_courses)


# ── Grade Route ───────────────────────────────────────────────────────────────
@app.route('/grades', methods=['GET', 'POST'])
@login_required
def grades():
    if current_user.role not in ['admin', 'teacher']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    all_students = Student.query.all()
    all_courses  = Course.query.all()
    all_grades   = Grade.query.all()
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id  = request.form.get('course_id')
        grade      = bleach.clean(request.form.get('grade'))
        remarks    = bleach.clean(request.form.get('remarks', ''))
        g = Grade(student_id=student_id, course_id=course_id,
                  grade=grade, remarks=remarks)
        db.session.add(g)
        db.session.commit()
        log_action(f'Recorded grade {grade} for student {student_id}')
        flash('Grade recorded successfully!', 'success')
        return redirect(url_for('grades'))
    return render_template('grades.html', students=all_students,
                           courses=all_courses, grades=all_grades)


# ── Attendance Route ──────────────────────────────────────────────────────────
@app.route('/attendance', methods=['GET', 'POST'])
@login_required
def attendance():
    if current_user.role not in ['admin', 'teacher']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    all_students   = Student.query.all()
    all_courses    = Course.query.all()
    all_attendance = Attendance.query.all()
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id  = request.form.get('course_id')
        date       = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        status     = request.form.get('status', 'Present')
        a = Attendance(student_id=student_id, course_id=course_id,
                       date=date, status=status)
        db.session.add(a)
        db.session.commit()
        log_action(f'Marked attendance for student {student_id}')
        flash('Attendance recorded successfully!', 'success')
        return redirect(url_for('attendance'))
    return render_template('attendance.html', students=all_students,
                           courses=all_courses, attendance=all_attendance)


# ── Audit Log Route ───────────────────────────────────────────────────────────
@app.route('/audit-logs')
@login_required
def audit_logs():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_logs.html', logs=logs)


# ── App Entry Point ───────────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        logger.info("Secure app started")
    app.run(debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true')