import datetime
import json
import os

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import  secure_filename
from app import app, db,login_manager,ALLOWED_EXTENSIONS
from flask import render_template, request, redirect, url_for, flash,  make_response, jsonify
from flask_login import login_user, login_required, current_user, logout_user
from model import User, Contact, Password, Book, Role,Order, BookOrder


@app.route('/')
def index():
    cartitems=request.cookies.get('bwcartitems')
    if cartitems:
        cartitems=json.loads(cartitems)
        cartitems={int(key):cartitems[key] for key in cartitems.key()}
    books = Book.query.all()
    return render_template('index.html',
                           books=books,cartitems=cartitems)

@app.route('/about')
def about():
    cartitems = request.cookies.get('bwcartitems')
    if cartitems:
        cartitems = json.loads(cartitems)
        cartitems = {int(key): cartitems[key] for key in cartitems.keys()}
    return render_template('about.html', cartitems=cartitems)


@app.route('/login',methods=['GET','POST'])
def login():
    cartitems = request.cookies.get('bwcartitems',None)
    if cartitems:
        cartitems =json.loads(cartitems)
        cartitems={int(key): cartitems[key] for key in cartitems.key()}

    if request.method == 'POST':
        email = request.form.get('email')
        remember = True if request.form.get('remember') else False
        contact = Contact.query.filter_by(email=email).first()
        if not contact:
            return redirect(url_for('.signup'))
        password = Password.query.filter_by(user_id=contact.user_id).first()
        pword = request.form.get('password')
        if not password or not check_password_hash(password.password, pword):
            flash('Please check your login details and try again.')
            # if the above check passes, then we know the user has the right credentials
            return redirect(url_for('.login'))  # if the user doesn't exist or password is wrong, reload the
        user = User.query.filter_by(id=contact.user_id).first()
        if not user:
            return redirect(url_for('.signup'))
        # if the above check passes, then we know the user has the right credentials
        login_user(user,remember=remember)

        return redirect(url_for('.profile', cartitems =cartitems ))
    return render_template('login.html',cartitems =cartitems)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('.index'))

@app.route('/profile')
@login_required
def profile():
    cartitems = request.cookies.get('bwcartitems', None)
    if cartitems:
        cartitems = json.loads(cartitems)
        cartitems = {int(key): cartitems[key] for key in cartitems.keys()}
    books = Book.query.filter_by(user_id=current_user.id).all()

    return render_template('profile.html',books=books,cartitems=cartitems)

@app.route('/signup')
def signup():
    cartitems = request.cookies.get('bwcartitems', None)
    if cartitems:
        cartitems = json.loads(cartitems)
        cartitems = {int(key): cartitems[key] for key in cartitems.keys()}
    return render_template("register.html", cartitems=cartitems)

@app.route('/register',methods=['POST'])
def register():
    email = request.form.get('email')
    contact = Contact.query.filter_by(email=email).first()
    # if this returns a user, then the email already exists in database
    if contact:  # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email not available.')
        return redirect(url_for('.signup'))
    fname = request.form.get('fname').strip()
    lname = request.form.get('lname').strip()
    phno = request.form.get('phone1').strip()
    pword = request.form.get('password').strip()
    cpword = request.form.get('cpassword').strip()
    add = request.form.get('address').strip()
    if pword != cpword or fname=='' or lname == '' or phno == '' or add == '' or pword == '' or cpword == '':
        flash('All field must not be empty and password and confirm password must be same')
        return redirect(url_for('.signup'))

        # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    user_password = Password(password=generate_password_hash(pword))
    user_contact = Contact(email=email, phone_number1=phno,address=add)
    user_role = Role.query.filter_by(name='author').first()

    new_user = User(first_name=fname, last_name=lname,  password=user_password,contact=user_contact,roles=[user_role])
    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    db.session.close()
    return redirect(url_for('.profile'))

@app.route('/createbook',methods=['GET','POST'])
@login_required
def createbook():
    cartitems = request.cookies.get('bwcartitems', None)
    if cartitems:
        cartitems = json.loads(cartitems)
        cartitems = {int(key): cartitems[key] for key in cartitems.keys()}
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        isbn = request.form.get('isbn', '').strip()
        year = request.form.get('year', '').strip()
        quantity = int(request.form.get('quantity', 0))
        description = request.form.get('description', '').strip()
        price = float(request.form.get('price', 0))

        if title == '' or isbn == '' or year == '' or \
                description == '' or price <= 0 or quantity <= 0:
            flash('No field must be empty')
            print(quantity)
            return redirect(request.url)
        if 'fil' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['fil']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if not file:
            flash('No file part')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('file not image file')
            return redirect(request.url)

        if not file.content_length <= 1024 * 1024:
            flash('file size too large')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            if not current_user.has_role('author'):
                role = Role.query.filter_by(name='author').first()
                User.query.filter_by(id=current_user.id).roles.append(role)
                db.session.commit()
            book = Book(title=title, isbn=isbn, year=year, description=description,
                        user_id=current_user.id, avquantity=quantity, price=price)
            db.session.add(book)
            db.session.commit()
            db.session.close()
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], title + '.jpg'))
            return redirect(url_for('.index'))
        flash('Book add failed')
        return redirect(request.url)
        # print('upload_dir',app.config['UPLOAD_DIR'])
        # print(os.path.join(os.getcwd(),'Static','file.txt'))
        # print(os.getcwd())
        # try:
        #     os.makedirs(UPLOAD_FOLDER,exist_ok=True)
        # except Exception as e:
        #     print(e)

    return render_template('views/bookview/create.html',cartitems=cartitems)

@app.route('/editbook',methods=['GET','POST'])
@login_required
def editbook():
    cartitems = request.cookies.get('bwcartitems', None)
    if cartitems:
        cartitems = json.loads(cartitems)
        cartitems = {int(key): cartitems[key] for key in cartitems.keys()}
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        isbn = request.form.get('isbn','').strip()
        year = request.form.get('year','').strip()
        quantity = int(request.form.get('quantity',0))
        description = request.form.get('description','').strip()
        price = float(request.form.get('price',0))
        bookid = request.form.get('id')
        if title == '' or isbn =='' or year =='' or \
            description == '' or price <= 0 or quantity <= 5:
            flash('No field must be empty')
            return redirect(url_for(request.url,id=bookid))

        if 'fil' in request.files:
            file = request.files['fil']
            if file :
                if not allowed_file(file.filename):
                    flash('file not image file')
                    return redirect(url_for(request.url,id=bookid))

            if not file.content_length <= 1024*1024:
                flash('file size too large')
                return redirect(request.url)

        book = Book.query.filter_by(id=bookid).first()
        success = book.update(title=title,isbn=isbn,description=description,
               year=year,price=price,avquantity=quantity)
        if success:
            # db.session.query(Book).filter(Book.id == bookid).update(
            #     {Book.title: title,Book.isbn:isbn,Book.year:year,
            #      Book.description:description}, synchronise_session=False)
                #db.session.add(book)
                db.session.commit()
                db.session.close()
            # file.save(os.path.join(app.config['UPLOAD_FOLDER'],title +'.jpg'))
                return redirect(url_for('.index'))
        flash('Book update failed')
        return redirect(url_for(request.url,id=bookid))
        # print('upload_dir',app.config['UPLOAD_DIR'])
        # print(os.path.join(os.getcwd(),'Static','file.txt'))
        # print(os.getcwd())
        # try:
        #     os.makedirs(UPLOAD_FOLDER,exist_ok=True)
        # except Exception as e:
        #     print(e)

    bkid = request.args.get('id',0)
    book = Book.query.filter_by(id=bkid).first()
    #if book:
    return render_template('views/bookview/edit.html',
                           book=book,cartitems=cartitems)

@app.route('/bookdetails')
def bookdetails():
    cartitems = request.cookies.get('bwcartitems', None)
    if cartitems:
        cartitems = json.loads(cartitems)
        cartitems = {int(key): cartitems[key] for key in cartitems.keys()}
    id = request.args.get('id')
    if id:
        book = Book.query.filter_by(id=id).first()
        return render_template('views/bookview/detail.html',
                               book=book,cartitems=cartitems)
    return redirect(redirect('.index'))


@app.route('/bookcarts')
def bookcarts():
    items = request.args.getlist('ids')
    quants = request.args.getlist('qtys')
    items = [int(items[i]) for i in range(len(items)) if int(quants[i]) > 0]
    quants = [int(quants[q]) for q in range(len(quants)) if int(quants[q]) > 0]
    print(items,quants)
    cartitems = None
    if len(items) > 0:
        cartitems = {id:qty for id,qty in zip(items,quants)}
    print(cartitems)
    if cartitems:
        books = Book.query.filter(Book.id.in_(items)).all()
        resp = make_response(render_template('views/bookview/cartitems.html',
                                             books=books, cartitems=cartitems))
        resp.set_cookie('bwcartitems',json.dumps(cartitems))
        return resp
    else:
        resp = make_response(redirect('/'))
        resp.delete_cookie('bwcartitems')
        return resp

@app.route('/updatecart',methods=['POST'])
def updatecart():
    cartitems = request.get_json()
    print(cartitems)
    ids = [id for id in list(cartitems['cartitems'].keys()) if cartitems['cartitems'][id] > 0 ]
    quants = [cartitems['cartitems'][id] for id in ids]
    print(ids,quants)
    if len(ids) > 0:
        cartitems = {int(id):qty for id,qty in zip(ids,quants)}
    else:
        cartitems = None
    resp = make_response(jsonify({'success':True}))
    if cartitems:
        print(cartitems)
        resp.set_cookie('bwcartitems',json.dumps(cartitems))
    else:
        resp.delete_cookie('bwcartitems')
    return resp

@app.route('/submitorder')
def submitorder():
    items = request.args.getlist('ids')
    quants = request.args.getlist('qtys')
    items = [int(items[i]) for i in range(len(items)) if int(quants[i]) > 0]
    quants = [int(quants[q]) for q in range(len(quants)) if int(quants[q]) > 0]
    print(items, quants)
    cartitems = {id: qty for id, qty in zip(items, quants)}
    print(cartitems)
    books = Book.query.filter(Book.id.in_(items)).all()
    resp = make_response(render_template('views/bookview/orderownerinfo.html',books=books,cartitems=cartitems))
    resp.set_cookie('bwcartitems',json.dumps(cartitems))
    return resp

@app.route('/saveorder',methods=['POST'])
def saveorder():
    cartitems = json.loads(request.cookies.get('bwcartitems'))
    cartitems = {int(id):qty for id,qty in zip(cartitems.keys(),cartitems.values())}
    email = request.form.get('email').strip()
    address = request.form.get('address').strip()
    books = Book.query.filter(Book.id.in_(cartitems.keys())).all()
    order = Order()

    bkqtysum = sum(cartitems.values())
    order.updateOrder(books=books,ord_quantity=bkqtysum,
                      ord_email=email, ord_address=address,
                      ord_delivered=True,)
    db.session.add(order)
    db.session.commit()
    for book in books:
        bookorder = BookOrder.query.filter_by(ord_id = order.id,book_id=book.id).first()
        bookorder.book_price = book.price
        bookorder.quantity = cartitems[book.id]
        db.session.commit()
    resp = make_response(render_template('views/bookview/ordersucces.html'))
    resp.delete_cookie("bwcartitems")
    return resp


@app.route('/admin')
@login_required
def getAdmin():
    return render_template('profile.html')


@login_manager.user_loader
def load_user(id):
    # since the user_id is just the primary key of
    # our user table, use it in the query for the user
    return User.query.get(int(id))
def allowed_file(filename):
    return '.'in filename and \
        filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS


