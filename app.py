
from curses import flash
from flask import Flask, request, jsonify, make_response, render_template,redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, BooleanField,EmailField
from wtforms.validators import InputRequired, Length,DataRequired
from flask_wtf import FlaskForm 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField
from _curses import *





app = Flask(__name__)
Bootstrap(app)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app = Flask(__name__)
bootstrap = Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:@localhost:3306/bitirme"


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'bitirme'

db = SQLAlchemy(app)





class Kullanici(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    mail= db.Column(db.String(50), unique=True)
    isim = db.Column(db.String(80))
    sifre = db.Column(db.String(80))
    bolum = db.Column(db.String(80))
    numara = db.Column(db.String(80))
    sinif = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

  
        

class Dersler(db.Model,UserMixin):
    ders_id = db.Column(db.Integer, primary_key=True)
    ders_adi = db.Column(db.String(80))
    ders_kodu = db.Column(db.String(80))
    ders_sinif = db.Column(db.String(80))
    ders_bolum = db.Column(db.String(80))
    ders_egitmen = db.Column(db.String(80))


class Egitmenler(db.Model,UserMixin):
    egitmen_id = db.Column(db.Integer, primary_key=True)
    egitmen_adi = db.Column(db.String(80))
    egitmen_soyadi = db.Column(db.String(80))
    egitmen_mail = db.Column(db.String(80))
    egitmen_bolum = db.Column(db.String(80))





def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if request.headers['x-access-token']:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'mesaj': 'Token bulunamadi!!'}), 401

        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Kullanici.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'mesaj': 'Token geçersiz!!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])

def listele():

    

    kullanicilar = Kullanici.query.all()
    output = []

    for kullanici in kullanicilar:
        kullanici_data = {}
        kullanici_data['id'] = kullanici.id
        kullanici_data['public_id'] = kullanici.public_id
        kullanici_data['isim'] = kullanici.isim
        kullanici_data['sifre'] = kullanici.sifre
        kullanici_data['numara'] = kullanici.numara
        kullanici_data['bolum'] = kullanici.bolum
        kullanici_data['sinif'] = kullanici.sinif
        kullanici_data['admin'] = kullanici.admin

        output.append(kullanici_data)

    return jsonify({'kullanicilar': output})
    


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def tek_kullanici(current_user, public_id):
    if not current_user.admin:
        return jsonify({'mesaj': 'Yetkiniz yok!!'})
    kullanici = Kullanici.query.filter_by(public_id=public_id).first()

    if not kullanici:
        return jsonify({'mesaj': 'Kullanici bulunamadi!'})

    kullanici_data = {}
    
    kullanici_data['isim'] = kullanici.isim
    kullanici_data['sifre'] = kullanici.sifre
    kullanici_data['numara'] = kullanici.numara
    kullanici_data['bolum'] = kullanici.bolum
    kullanici_data['sinif'] = kullanici.sinif
    kullanici_data['admin'] = kullanici.admin

    return jsonify({'kullanici': kullanici_data})


@app.route('/kayitol', methods=['POST'])
def kullanici_olustur():
    data = request.get_json()
    hashed_password = generate_password_hash(data['sifre'], method='sha256')
    yeni_kullanici = Kullanici(
        public_id=[uuid.uuid1()], 
        isim=data['isim'],
        mail=data['mail'], 
        sifre=hashed_password, 
        bolum=data['bolum'], 
        numara=data['numara'], 
        sinif=data['sinif'], 
        admin=False)
    db.session.add(yeni_kullanici)
    db.session.commit()

    return jsonify({'message': 'Yeni kullanici olusturuldu!'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def kullanici_guncelle(current_user, public_id):
    if not current_user.admin:
        return jsonify({'mesaj': 'Yetkiniz yok!!'})
    kullanici = Kullanici.query.filter_by(public_id=public_id).first()
   

    if not kullanici:
        return jsonify({'mesaj': 'Kullanici bulunamadi!'})

    kullanici.admin = True
    db.session.commit()

    return jsonify({'mesaj': 'Kullanici guncellendi!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def kullanici_sil(current_user, public_id):
    if not current_user.admin:
        return jsonify({'mesaj': 'Yetkiniz yok!!'})
    kullanici = Kullanici.query.filter_by(public_id=public_id).first()
    if not kullanici:
        return jsonify({'mesaj': 'Kullanici bulunamadi!'})
    db.session.delete(kullanici)
    db.session.commit()
    return jsonify({'mesaj': 'Kullanici silindi!'})


@app.route('/giris')
def giris():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'token': "eksik veri gonderdiniz"}), 401 

    user = Kullanici.query.filter_by(numara=auth.username).first()
    

    if not user:
        return jsonify({'token': "kullanici bulunamadi"}), 401
    if check_password_hash(user.sifre, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=20)}, app.config['SECRET_KEY'], algorithm="HS256")
        kullanici=({'kullanici_adi': user.isim, 'kullanici_numarasi': user.numara, 'kullanici_bolumu': user.bolum, 'kullanici_sinifi': user.sinif, 'kullanici_admin': user.admin})

        return jsonify({'token': token,'kullanici_bilgisi':kullanici}), 200
        


    return jsonify({'token': "hatalı giris"}), 401


@app.route('/ders', methods=['GET'])
@token_required
def ders_listele(current_user):

    if not current_user.admin:
        return jsonify({'mesaj': 'Yetkiniz yok!!'})

    dersler = Dersler.query.all()
    output = []

    for ders in dersler:
        ders_data = {}
        ders_data['ders_id'] = ders.ders_id
        ders_data['ders_adi'] = ders.ders_adi
        ders_data['ders_kodu'] = ders.ders_kodu
        ders_data['ders_sinif'] = ders.ders_sinif
        ders_data['ders_bolum'] = ders.ders_bolum
        ders_data['ders_egitmen'] = ders.ders_egitmen

        output.append(ders_data)

    return jsonify({'Dersler': output})


@app.route('/ders/<ders_id>', methods=['GET'])
@token_required
def tek_ders_listele(current_user, ders_id):
    if not current_user.admin:
        return jsonify({'mesaj': 'Yetkiniz yok!!'})
    ders = Dersler.query.filter_by(ders_id=ders_id).first()

    if not ders:
        return jsonify({'mesaj': 'Ders bulunamadi!'})

    ders_data = {}
    ders_data['ders_id'] = ders.ders_id
    ders_data['ders_adi'] = ders.ders_adi
    ders_data['ders_kodu'] = ders.ders_kodu
    ders_data['ders_sinif'] = ders.ders_sinif
    ders_data['ders_bolum'] = ders.ders_bolum
    ders_data['egitmen'] = ders.egitmen

    return jsonify({'Ders': ders_data})


@app.route('/ders', methods=['POST'])
@token_required
def ders_olustur(current_user):
    if not current_user.admin:
        return jsonify({'mesaj': 'Yetkiniz yok!!'})
    data = request.get_json()

    yeni_ders = Dersler(ders_id=data['ders_id'], ders_adi=data['ders_adi'], ders_kodu=data['ders_kodu'],
                        ders_sinif=data['ders_sinif'], ders_egitmen=data['ders_egitmen'])
    db.session.add(yeni_ders)
    db.session.commit()

    return jsonify({'message': 'Yeni ders olusturuldu!'})


@app.route('/user/<ders_id>', methods=['PUT'])
@token_required
def ders_guncelle(current_user, ders_id):
    if not current_user.admin:
        return jsonify({'mesaj': 'Yetkiniz yok!!'})
    kullanici = Kullanici.query.filter_by(ders_id=ders_id).first()

    if not kullanici:
        return jsonify({'mesaj': 'Ders bulunamadi!'})

    db.session.commit()

    return jsonify({'mesaj': 'ders guncellendi!'})


@app.route('/ders/<ders_id>', methods=['DELETE'])
@token_required
def ders_sil(current_user, ders_id):
    if not current_user.admin:
        return jsonify({'mesaj': 'Yetkiniz yok!!'})
    ders = Dersler.query.filter_by(ders_id=ders_id).first()
    if not ders:
        return jsonify({'mesaj': 'Ders bulunamadi!'})
    db.session.delete(ders)
    db.session.commit()
    return jsonify({'mesaj': 'Ders silindi!'})















































# YÖNETİCİ İŞLEMLERİ



@login_manager.user_loader
def load_user(public_id):
    return Kullanici.query.get(int(public_id))
   
class LoginForm(FlaskForm):
    isim = StringField('isim', validators=[InputRequired(), Length(min=1, max=15)])
    sifre = PasswordField('sifre', validators=[InputRequired(), Length(min=4, max=80)])
    remember = BooleanField('Beni Hatırla')

class kullaniciEkle(FlaskForm):
    isim = StringField('isim', validators=[DataRequired(), Length(min=1, max=15)])
    sifre = PasswordField('sifre', validators=[DataRequired(), Length(min=4, max=80)])
    mail= StringField('mail', validators=[DataRequired(), Length(min=1, max=100)])
    bolum = StringField('bolum', validators=[DataRequired(), Length(min=1, max=100)])
    numara = StringField('numara', validators=[DataRequired(), Length(min=1, max=15)])
    sinif = StringField('sinif', validators=[DataRequired(), Length(min=1, max=15)])
    admin = BooleanField('admin')

class dersEkle(FlaskForm):
  
    ders_adi = StringField('ders_adi', validators=[DataRequired(), Length(min=1, max=1000)])
    ders_kodu = StringField('ders_kodu', validators=[DataRequired(), Length(min=1, max=1000)])
    ders_sinif = StringField('ders_sinif', validators=[DataRequired(), Length(min=1, max=1000)])
    ders_bolum = StringField('ders_bolum', validators=[DataRequired(), Length(min=1, max=1000)])
    ders_egitmen = StringField('ders_egitmen', validators=[DataRequired(), Length(min=1, max=1000)])

class egitmenEkle(FlaskForm):
    egitmen_id = StringField('egitmen_id', validators=[DataRequired(), Length(min=1, max=300)])
    egitmen_adi = StringField('egitmen_adi', validators=[DataRequired(), Length(min=1, max=100)])
    egitmen_soyadi = StringField('egitmen_soyadi', validators=[DataRequired(), Length(min=1, max=30)])
    egitmen_mail = EmailField('egitmen_mail', validators=[DataRequired(), Length(min=1, max=30)])
    egitmen_bolum = StringField('egitmen_bolum', validators=[DataRequired(), Length(min=1, max=15)])


class egitmenGuncelle(FlaskForm):
    egitmen_id= StringField('egitmen_id', validators=[DataRequired(), Length(min=1, max=1000)])
    egitmen_adi = StringField('egitmen_adi', validators=[DataRequired(), Length(min=1, max=1000)])
    egitmen_soyadi = StringField('egitmen_soyadi', validators=[DataRequired(), Length(min=1, max=1000)])
    egitmen_mail = EmailField('egitmen_mail', validators=[DataRequired(), Length(min=1, max=1000)])
    egitmen_bolum = StringField('egitmen_bolum', validators=[DataRequired(), Length(min=1, max=1000)])
    
class dersGuncelle(FlaskForm):
    ders_adi = StringField('ders_adi', validators=[DataRequired(), Length(min=1, max=1000)])
    ders_kodu = StringField('ders_kodu', validators=[DataRequired(), Length(min=1, max=1000)])
    ders_sinif = StringField('ders_sinif', validators=[DataRequired(), Length(min=1, max=1000)])
    ders_bolum = StringField('ders_bolum', validators=[DataRequired(), Length(min=1, max=1000)])
    ders_egitmen = StringField('ders_egitmen', validators=[DataRequired(), Length(min=1, max=1000)])  

class kullaniciGuncelle(FlaskForm):
    isim = StringField('isim', validators=[DataRequired(), Length(min=1, max=15)])
    sifre = PasswordField('sifre', validators=[DataRequired(), Length(min=4, max=80)])
    mail= StringField('mail', validators=[DataRequired(), Length(min=1, max=100)])
    bolum = StringField('bolum', validators=[DataRequired(), Length(min=1, max=100)])
    numara = StringField('numara', validators=[DataRequired(), Length(min=1, max=15)])
    sinif = StringField('sinif', validators=[DataRequired(), Length(min=1, max=15)])
    admin = BooleanField('admin')
    
    
@app.route('/')
def index():
    return render_template('index.html')




@app.route('/login', methods=['GET', 'POST'], strict_slashes=False)
def login():
    form = LoginForm()
    kull = Kullanici.query.filter_by(isim=form.isim.data).first()
    if kull:
            if check_password_hash(kull.sifre, form.sifre.data):
                login_user(kull, remember=form.remember.data)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)




@app.route('/dashboard', strict_slashes=False)
@login_required
def dashboard():
    return render_template('dashboard.html',
    id = current_user.public_id,
    isim=current_user.isim ,
    numara = current_user.numara, 
    bolum = current_user.bolum, 
    sinif = current_user.sinif, 

    )


@app.route('/kullanici_listele',methods=['GET' ,'POST'] ,strict_slashes=False)
@login_required
def kullanici_listele():
    kullaniciIslem = Kullanici.query.all()
    return render_template('kullanici_listele.html', kullaniciIslem=kullaniciIslem)


@app.route('/kullanici_ekle',methods=['GET','POST'] ,strict_slashes=False)
@login_required
def kullanici_ekle():
    form = kullaniciEkle()
    if request.method == 'POST':
            public_id = str(uuid.uuid4())
            isim = form.isim.data
            sifre = generate_password_hash(form.sifre.data, method='sha256')
            mail = form.mail.data
            bolum = form.bolum.data
            numara = form.numara.data
            sinif = form.sinif.data
            admin = form.admin.data
            yeni_kullanici = Kullanici(public_id=public_id,isim=isim, sifre=sifre,mail=mail, bolum=bolum, numara=numara, sinif=sinif,admin=admin)
            db.session.add(yeni_kullanici)
            db.session.commit()
            return redirect(url_for('kullanici_listele'))
    return render_template('kullanici_ekle.html', form=form)

@app.route('/kullanici_sil',methods=['GET','POST'] ,strict_slashes=False)
@login_required
def kullanici_sil_render():
    kullaniciIslem = Kullanici.query.all()
    return render_template('kullanici_sil.html', kullaniciIslem=kullaniciIslem)

@app.route('/kullanici_sil/<id>',methods=['GET','POST'] ,strict_slashes=False)
@login_required
def kullanici_silme(id):
    kullanici = Kullanici.query.filter_by(public_id=id).first()
    db.session.delete(kullanici)
    db.session.commit()
    return redirect(url_for('kullanici_listele'))


@app.route('/kullanici_guncelle',methods=['GET','POST'] ,strict_slashes=False)
@login_required
def kullanici_guncelle_render():
    kullaniciIslem = Kullanici.query.all()
    return render_template('kullanici_guncelle.html', kullaniciIslem=kullaniciIslem)

@app.route('/kullanici_guncelle/<id>',methods=['GET','POST'] ,strict_slashes=False)
@login_required
def kullanici_guncelleme(id):
    form = kullaniciGuncelle()
    kullanici = Kullanici.query.filter_by(public_id=id).first()
    isim = form.isim.data
    sifre = form.sifre.data
    mail = form.mail.data
    bolum = form.bolum.data
    numara = form.numara.data
    sinif = form.sinif.data
    admin = form.admin.data
    db.session.delete(kullanici)
    db.session.commit()
    if request.method == 'POST':
        public_id = str(uuid.uuid4())
        isim=form.isim.data
        sifre=generate_password_hash(form.sifre.data, method='sha256')
        mail=form.mail.data
        bolum=form.bolum.data
        numara=form.numara.data
        sinif=form.sinif.data
        admin=form.admin.data
        yeni_kullanici = Kullanici(public_id=public_id,isim=isim, sifre=sifre,mail=mail, bolum=bolum, numara=numara, sinif=sinif,admin=admin)
        db.session.add(yeni_kullanici)
        db.session.commit()

        return redirect(url_for('kullanici_listele'))
    return render_template('kullanici_ekle.html', form=form, kullanici=kullanici)


@app.route('/ders-islemleri', strict_slashes=False)
@login_required
def ders_islemleri():
    dersIslem = Dersler.query.all()
    return render_template('ders_listele.html', dersIslem=dersIslem)



@app.route('/ders_ekle',methods=['GET','POST'] ,strict_slashes=False)
@login_required
def ders_ekle():
    form = dersEkle()
    if request.method == 'POST':
            
            ders_adi = form.ders_adi.data
            ders_kodu = form.ders_kodu.data
            ders_sinif = form.ders_sinif.data
            ders_bolum = form.ders_bolum.data
            ders_egitmen = form.ders_egitmen.data
            yeni_ders = Dersler(ders_adi=ders_adi, ders_kodu=ders_kodu, ders_sinif=ders_sinif, ders_bolum=ders_bolum, ders_egitmen=ders_egitmen)
            db.session.add(yeni_ders)
            db.session.commit()
            return redirect(url_for('ders_islemleri'))
    return render_template('ders_ekle.html', form=form)
   

@app.route('/ders_sil', methods=['GET', 'POST'], strict_slashes=False) 
@login_required
def ders_sil_render():
    dersIslem = Dersler.query.all()
    return render_template('ders_sil.html', dersIslem=dersIslem)

@app.route('/ders_sil/<id>', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def ders_silme(id):
    ders = Dersler.query.filter_by(ders_id=id).first()
    db.session.delete(ders)
    db.session.commit()
    return redirect(url_for('ders_islemleri'))

@app.route('/ders_guncelle', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def ders_guncelle_render():
    dersIslem = Dersler.query.all()
    return render_template('ders_guncelle.html', dersIslem=dersIslem)

@app.route('/ders_guncelle/<id>', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def ders_guncelleme(id):
    form = dersGuncelle()
    ders = Dersler.query.filter_by(ders_id=id).first()
    ders_adi = ders.ders_adi
    ders_kodu = ders.ders_kodu
    ders_sinif = ders.ders_sinif
    ders_bolum = ders.ders_bolum
    ders_egitmen = ders.ders_egitmen
    db.session.delete(ders)
    db.session.commit()
    if request.method == 'POST':
        ders_adi = form.ders_adi.data
        ders_kodu = form.ders_kodu.data
        ders_sinif = form.ders_sinif.data
        ders_bolum = form.ders_bolum.data
        ders_egitmen = form.ders_egitmen.data
        guncel_ders= Dersler(ders_adi=ders_adi, ders_kodu=ders_kodu, ders_sinif=ders_sinif, ders_bolum=ders_bolum, ders_egitmen=ders_egitmen)
        db.session.add(guncel_ders)
        db.session.commit()
        return redirect(url_for('ders_islemleri'))
    return render_template('ders_ekle.html', form=form)



@app.route('/egitmen-islemleri', strict_slashes=False)
@login_required
def egitmen_islemleri():
    egitmenIslem = Egitmenler.query.all()
    return render_template('egitmen_listele.html', egitmenIslem=egitmenIslem)

@app.route('/egitmen_ekle',methods=['GET','POST'] ,strict_slashes=False)
@login_required
def egitmen_ekle():
    form = egitmenEkle()
    if request.method == 'POST':
        egitmen_id = form.egitmen_id.data
        egitmen_adi = form.egitmen_adi.data
        egitmen_soyadi = form.egitmen_soyadi.data
        egitmen_mail = form.egitmen_mail.data
        egitmen_bolum = form.egitmen_bolum.data
       
        yeni_egitmen = Egitmenler(egitmen_id=egitmen_id,egitmen_adi=egitmen_adi, egitmen_soyadi=egitmen_soyadi, egitmen_mail=egitmen_mail, egitmen_bolum=egitmen_bolum)
        db.session.add(yeni_egitmen)
        db.session.commit()
        return redirect(url_for('egitmen_islemleri'))
    return render_template('egitmen_ekle.html', form=form)

@app.route('/egitmen_sil' , methods=['GET'], strict_slashes=False)
@login_required
def egitmen_sil_render():
    egitmen = Egitmenler.query.all()
    return render_template('egitmen_sil.html', egitmen=egitmen) 

@app.route('/egitmen_sil/<id>', methods=['GET'], strict_slashes=False)
@login_required
def egitmen_silme(id):
        egitmen = Egitmenler.query.filter_by(egitmen_id=id).first()
        db.session.delete(egitmen)
        db.session.commit()
        return redirect(url_for('egitmen_islemleri'))

@app.route('/egitmen_guncelle' , methods=['GET'], strict_slashes=False)
@login_required

def egitmen_guncelle_render():
    
    egitmen = Egitmenler.query.all()
    return render_template('egitmen_guncelle.html', egitmen=egitmen)


@app.route('/egitmen_guncelle/<id>', methods=['GET','POST'], strict_slashes=False)        
@login_required
def egitmen_guncelle(id):
    form = egitmenGuncelle()
    egitmen = Egitmenler.query.filter_by(egitmen_id=id).first()
    egitmen_adi=egitmen.egitmen_adi
    egitmen_soyadi=egitmen.egitmen_soyadi
    egitmen_mail=egitmen.egitmen_mail
    egitmen_bolum=egitmen.egitmen_bolum
    db.session.delete(egitmen)
    db.session.commit()
    if request.method == ['POST','GET']:
        
        egitmen_adi = form.egitmen_adi.data
        egitmen_soyadi = form.egitmen_soyadi.data
        egitmen_mail = form.egitmen_mail.data 
        egitmen_bolum = form.egitmen_bolum.data
        yeni_egitmen = Egitmenler(egitmen_id=id,egitmen_adi=egitmen_adi, egitmen_soyadi=egitmen_soyadi, egitmen_mail=egitmen_mail, egitmen_bolum=egitmen_bolum)
        db.session.add(yeni_egitmen)
        db.session.commit() 
        return redirect(url_for('egitmen_islemleri'))       
    return render_template('egitmen_ekle.html', form=form)

    
 
    

    
    
    
    
    
    
    
    
    

   

 
   
  
    
     
           
    
@app.route('/qr_kod', strict_slashes=False)
@login_required
def qr_kod():

    return render_template('qr_kod.html', isim=current_user.isim , numara = current_user.numara)








@app.route("/logout")
@login_required
def logout():
    logout_user()
    
    return redirect(url_for('login'))





if __name__ == "__main__":
    app.run('0.0.0.0', debug=True)
