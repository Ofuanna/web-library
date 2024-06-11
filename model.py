import datetime
from sqlalchemy import ForeignKey,CheckConstraint,DECIMAL
from sqlalchemy.orm import relationship
from app import db

from flask_login import UserMixin
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    contact = relationship("Contact", uselist=False, backref="user")
    password = relationship('Password',uselist=False,backref='user')
    books = relationship('Book', backref="user")
    roles = relationship('Role', secondary='user_role', backref="user")

    def __repr__(self):
        return "User('%s %s')" % (
            self.first_name, self.last_name)

    def __str__(self):
        return "%s %s" %(self.first_name, self.last_name)

    def has_role(self,role):
        return Role.query.join(Role.users) \
        .filter(User.id == self.id) \
        .filter(Role.name == role).count() > 0

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300),unique=True)
    isbn = db.Column(db.String(11), unique=True)
    year = db.Column(db.String(4))
    description = db.Column(db.String(500))
    avquantity = db.Column(db.Integer,
                    CheckConstraint('avquantity > 0'), nullable = False)
    price = db.Column(DECIMAL(precision=10, scale=2),
                    CheckConstraint('price > 0'), nullable = False)
    user_id = db.Column(db.Integer, ForeignKey('user.id'))
    orders = relationship('Order', secondary='book_order', backref='book')

    def get_user(self):
        return User.query.filter_by(id=self.user_id).first()

    def update(self, title=title, isbn=isbn, description=description,
               year=year, avquantity=avquantity, price=price):
        if self.title != title:
            self.title = title
        if self.isbn != isbn:
            self.isbn = isbn
        if self.year != year:
            self.year = year
        if self.description != description:
            self.description = description
        if self.avquantity != int(avquantity) and int(avquantity) > 0:
            self.avquantity = avquantity;
        if self.price != price and price > 0:
            self.price = price
        return True

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone_number1 = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    address = db.Column(db.String(200))
    user_id = db.Column(db.Integer, ForeignKey('user.id'))

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(200), unique=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'))

class Role(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(20), unique = True,)
    users = relationship('User',secondary='user_role',backref="role")

class UserRole(db.Model):
    user_id = db.Column(db.Integer, ForeignKey('user.id'), primary_key=True)
    role_id = db.Column(db.Integer, ForeignKey('role.id'), primary_key=True)
#
# class UserBook(db.Model):
#     user_id = db.Column(db.Integer, ForeignKey('user.id'), primary_key=True)
#     book_id = db.Column(db.Integer, ForeignKey('book.id'), primary_key=True)

class Order(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    ord_quantity = db.Column(db.Integer,
                CheckConstraint('ord_quantity > 0'),nullable=False)
    ord_date = db.Column(db.DateTime,default=datetime.datetime.utcnow)
    shipped_date = db.Column(db.DateTime,default= datetime.datetime.utcnow)
    ord_address = db.Column(db.String(200))
    ord_email = db.Column(db.String(50))
    ord_delivered = db.Column(db.Boolean,default=False)
    books = relationship('Book',secondary='book_order',backref='order')

    def updateOrder(self,books=books,ord_quantity=ord_quantity,shipped_date=shipped_date,
                    ord_address=ord_address,ord_email=ord_email,
                    ord_delivered=ord_delivered):
        self.ord_quantity = ord_quantity
        #self.shipped_date = shipped_date
        self.ord_address = ord_address
        self.ord_email = ord_email
        self.ord_delivered = ord_delivered
        self.books.extend(books)


class BookOrder(db.Model):
    ord_id = db.Column(db.Integer,ForeignKey('order.id'),primary_key=True)
    book_id = db.Column(db.Integer,ForeignKey('book.id'),primary_key=True)
    book_price = db.Column(DECIMAL(precision=10,scale=2),
                           CheckConstraint('book_price >= 0'),nullable=False,default=0.0)
    quantity = db.Column(db.Integer,CheckConstraint('quantity >= 0'),default=0)

    def updatebookorder(self,book_price,quantity):
        self.book_price = book_price
        self.quantity = quantity


