from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, Student, Course, Enrollment, Grade, Attendance
from datetime import date
import logging

students_bp = Blueprint('students', __name__)
logger = logging.getLogger(__name__)

@students_bp.route('/students')
@login_required
def list_students():
    students = Student.query.all()
    logger.info(f"User {current_user.username} viewed student list")
    return render_template('students/list.html', students=students)

@students_bp.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('students.list_students'))
    if request.method == 'POST':
        student_id = request.form.get('student_id', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        if not student_id or not full_name or not email:
            flash('Student ID, name and email are required.', 'danger')
            return render_template('students/add.html')
        if Student.query.filter_by(student_id=student_id).first():
            flash('Student ID already exists.', 'danger')
            return render_template('students/add.html')
        student = Student(student_id=student_id, full_name=full_name,
                         email=email, phone=phone)
        db.session.add(student)
        db.session.commit()
        logger.info(f"Admin {current_user.username} added student {student_id}")
        flash(f'Student {full_name} added!', 'success')
        return redirect(url_for('students.list_students'))
    return render_template('students/add.html')

@students_bp.route('/students/delete/<int:id>', methods=['POST'])
@login_required
def delete_student(id):
    if current_user.role != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('students.list_students'))
    student = Student.query.get_or_404(id)
    db.session.delete(student)
    db.session.commit()
    logger.info(f"Admin {current_user.username} deleted student {student.student_id}")
    flash('Student deleted.', 'success')
    return redirect(url_for('students.list_students'))

@students_bp.route('/courses')
@login_required
def list_courses():
    courses = Course.query.all()
    return render_template('students/courses.html', courses=courses)

@students_bp.route('/courses/add', methods=['GET', 'POST'])
@login_required
def add_course():
    if current_user.role != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('students.list_courses'))
    if request.method == 'POST':
        course_code = request.form.get('course_code', '').strip()
        course_name = request.form.get('course_name', '').strip()
        description = request.form.get('description', '').strip()
        if not course_code or not course_name:
            flash('Course code and name required.', 'danger')
            return render_template('students/add_course.html')
        course = Course(course_code=course_code, course_name=course_name,
                       description=description)
        db.session.add(course)
        db.session.commit()
        flash(f'Course {course_name} added!', 'success')
        return redirect(url_for('students.list_courses'))
    return render_template('students/add_course.html')

@students_bp.route('/enroll', methods=['GET', 'POST'])
@login_required
def enroll():
    if current_user.role != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('students.list_students'))
    students = Student.query.all()
    courses = Course.query.all()
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id = request.form.get('course_id')
        existing = Enrollment.query.filter_by(
            student_id=student_id, course_id=course_id).first()
        if existing:
            flash('Already enrolled.', 'warning')
        else:
            enrollment = Enrollment(student_id=student_id, course_id=course_id)
            db.session.add(enrollment)
            db.session.commit()
            flash('Student enrolled!', 'success')
        return redirect(url_for('students.enroll'))
    return render_template('students/enroll.html', students=students, courses=courses)

@students_bp.route('/grades', methods=['GET', 'POST'])
@login_required
def grades():
    if current_user.role != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('students.list_students'))
    students = Student.query.all()
    courses = Course.query.all()
    all_grades = Grade.query.all()
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id = request.form.get('course_id')
        grade_val = request.form.get('grade', '').strip()
        remarks = request.form.get('remarks', '').strip()
        if not grade_val:
            flash('Grade is required.', 'danger')
        else:
            grade = Grade(student_id=student_id, course_id=course_id,
                         grade=grade_val, remarks=remarks)
            db.session.add(grade)
            db.session.commit()
            flash('Grade recorded!', 'success')
        return redirect(url_for('students.grades'))
    return render_template('students/grades.html',
                           students=students, courses=courses, grades=all_grades)

@students_bp.route('/attendance', methods=['GET', 'POST'])
@login_required
def attendance():
    if current_user.role != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('students.list_students'))
    students = Student.query.all()
    courses = Course.query.all()
    all_attendance = Attendance.query.order_by(Attendance.date.desc()).all()
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id = request.form.get('course_id')
        status = request.form.get('status', 'Present')
        record = Attendance(student_id=student_id, course_id=course_id,
                           date=date.today(), status=status)
        db.session.add(record)
        db.session.commit()
        flash('Attendance recorded!', 'success')
        return redirect(url_for('students.attendance'))
    return render_template('students/attendance.html',
                           students=students, courses=courses,
                           attendance=all_attendance)