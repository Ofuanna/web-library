from app import app,db,UPLOAD_FOLDER
from routes import *
from model import *
from werkzeug.utils import secure_filename
import os

if __name__ == '__main__':
    app.app_context().push()
    role_count = len(db.session.query(Role).all())
    if role_count <= 0:
        db.session.add_all([Role(name="admin"), Role(name="author")])
        db.session.commit()
        db.session.close()
    users = User.query.all()
    if len(users) <= 0:
        admin_contact = Contact(email='admin@gmail.com',phone_number1='09122334455')
        user_password = Password(password=generate_password_hash('admin_user'))
        admin_role = Role.query.filter_by(name = 'admin').first()
        admin_user = User(first_name='Admin', last_name='Admin',password=user_password, roles=[admin_role],contact=admin_contact)
        db.session.add(admin_user)
        db.session.commit()
        db.session.close()

app.run(debug=True)