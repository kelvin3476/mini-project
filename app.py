import hashlib
import datetime
import jwt
from pymongo import MongoClient
from bson.objectid import ObjectId
import matplotlib.pyplot as plt
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
app = Flask(__name__)

client = MongoClient('localhost', 27017)
db = client.dbPUMG

# JWT 토큰을 만들 때 필요한 비밀문자열입니다. 아무거나 입력해도 괜찮습니다.
# 이 문자열은 서버만 알고있기 때문에, 내 서버에서만 토큰을 인코딩(=만들기)/디코딩(=풀기) 할 수 있습니다.
SECRET_KEY = 'zerocoke'

# JWT 패키지를 사용합니다. (설치해야할 패키지 이름: PyJWT)

# 토큰에 만료시간을 줘야하기 때문에, datetime 모듈도 사용합니다.

# 회원가입 시엔, 비밀번호를 암호화하여 DB에 저장해두는 게 좋습니다.
# 그렇지 않으면, 개발자(=나)가 회원들의 비밀번호를 볼 수 있으니까요.^^;

#################################
##  HTML을 주는 부분             ##
#################################


@app.route('/')
def home():
   return render_template('main.html')


@app.route('/login')
def login():
   return render_template('login.html')


@app.route('/register')
def register():
   return render_template('register.html')

@app.route('/mypage')
def mypage():
   return render_template('mypage.html')

#################################
##  로그인을 위한 API            ##
#################################

# [회원가입 API]
# id, pw, nickname을 받아서, mongoDB에 저장합니다.
# 저장하기 전에, pw를 sha256 방법(=단방향 암호화. 풀어볼 수 없음)으로 암호화해서 저장합니다.


@app.route('/api/register', methods=['GET','POST'])
def api_register():
   if request.method == 'POST':
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    nickname_receive = request.form['nickname_give']
    name_receive = request.form['name_give']
    laptop_os_receive = request.form['laptop_os_give']
    laptop_receive = request.form['laptop_give']
    cellphone_os_receive = request.form['cellphone_os_give']
    cellphone_receive = request.form['cellphone_give']
    keyboard_receive = request.form['keyboard_give']
    mouse_receive = request.form['mouse_give']

    # Validate form fields
    if not id_receive or not pw_receive or not nickname_receive or not name_receive:
       return jsonify({'result': 'fail','msg':'빈칸을 입력해주세요!'})
    
    # check if user already exists
    if db.user.find_one({'id': id_receive }):
           return jsonify({'result': 'fail','msg':'중복된 아이디 입니다.'})

   pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()
   
   db.user.insert_one({'id': id_receive, 'pw': pw_hash, 'nick': nickname_receive, 'name': name_receive, 'laptop_os': laptop_os_receive, 'laptop': laptop_receive, 'cellphone_os': cellphone_os_receive, 'cellphone': cellphone_receive, 'keyboard': keyboard_receive, 'mouse': mouse_receive})

   return jsonify({'result': 'success'})

# [로그인 API]
# id, pw를 받아서 맞춰보고, 토큰을 만들어 발급합니다.
@app.route('/api/login', methods=['POST'])
def api_login():
   id_receive = request.form['id_give']
   pw_receive = request.form['pw_give']

   # 회원가입 때와 같은 방법으로 pw를 암호화합니다.
   pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

   # id, 암호화된pw을 가지고 해당 유저를 찾습니다.
   result = db.user.find_one({'id':id_receive,'pw':pw_hash})

   # 찾으면 JWT 토큰을 만들어 발급합니다.
   if result is not None:
      # JWT 토큰에는, payload와 시크릿키가 필요합니다.
      # 시크릿키가 있어야 토큰을 디코딩(=풀기) 해서 payload 값을 볼 수 있습니다.
      # 아래에선 id와 exp를 담았습니다. 즉, JWT 토큰을 풀면 유저ID 값을 알 수 있습니다.
      # exp에는 만료시간을 넣어줍니다. 만료시간이 지나면, 시크릿키로 토큰을 풀 때 만료되었다고 에러가 납니다.
      payload = {
         'id': id_receive,
         'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
      }
      token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

      # token을 줍니다.
      return jsonify({'result': 'success','token':token})
   # 찾지 못하면
   else:
      return jsonify({'result': 'fail', 'msg':'아이디/비밀번호가 일치하지 않습니다.'})

# [유저 정보 확인 API]
# 로그인된 유저만 call 할 수 있는 API입니다.
# 유효한 토큰을 줘야 올바른 결과를 얻어갈 수 있습니다.
# (그렇지 않으면 남의 장바구니라든가, 정보를 누구나 볼 수 있겠죠?)
@app.route('/api/nick', methods=['GET'])
def api_valid():
   # 토큰을 주고 받을 때는, 주로 header에 저장해서 넘겨주는 경우가 많습니다.
   # header로 넘겨주는 경우, 아래와 같이 받을 수 있습니다.
   token_receive = request.headers['token_give']

   # try / catch 문?
   # try 아래를 실행했다가, 에러가 있으면 except 구분으로 가란 얘기입니다.

   try:
      # token을 시크릿키로 디코딩합니다.
      # 보실 수 있도록 payload를 print 해두었습니다. 우리가 로그인 시 넣은 그 payload와 같은 것이 나옵니다.
      payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
      print(payload)

      # payload 안에 id가 들어있습니다. 이 id로 유저정보를 찾습니다.
      # 여기에선 그 예로 닉네임을 보내주겠습니다.
      userinfo = db.user.find_one({'id':payload['id']},{'_id':0})
      return jsonify({'result': 'success','nickname':userinfo['nick']})
   except jwt.ExpiredSignatureError:
      # 위를 실행했는데 만료시간이 지났으면 에러가 납니다.
      return jsonify({'result': 'fail', 'msg':'로그인 시간이 만료되었습니다.'})
   
# [유저 정보 확인 API]
# 로그인된 유저만 call 할 수 있는 API입니다.
# 유효한 토큰을 줘야 올바른 결과를 얻어갈 수 있습니다.
# (그렇지 않으면 남의 장바구니라든가, 정보를 누구나 볼 수 있겠죠?)
@app.route('/api/mypage', methods=['GET'])
def my_info_valid():
   # 토큰을 주고 받을 때는, 주로 header에 저장해서 넘겨주는 경우가 많습니다.
   # header로 넘겨주는 경우, 아래와 같이 받을 수 있습니다.
   token_receive = request.headers['token_give']

   # try / catch 문?
   # try 아래를 실행했다가, 에러가 있으면 except 구분으로 가란 얘기입니다.

   try:
      # token을 시크릿키로 디코딩합니다.
      # 보실 수 있도록 payload를 print 해두었습니다. 우리가 로그인 시 넣은 그 payload와 같은 것이 나옵니다.
      payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
      print(payload)

      # payload 안에 id가 들어있습니다. 이 id로 유저정보를 찾습니다.
      # 여기에선 그 예로 닉네임을 보내주겠습니다.
      userinfo = db.user.find_one({'id':payload['id']},{'_id':0})
      return jsonify({'result': 'success','userinfo':userinfo })
   except jwt.ExpiredSignatureError:
      # 위를 실행했는데 만료시간이 지났으면 에러가 납니다.
      return jsonify({'result': 'fail', 'msg':'로그인 시간이 만료되었습니다.'})
   
@app.route('/api/main', methods=['GET'])
def card_info():
   
   userinfo = list(db.user.find({}, {'_id':0}))
   return jsonify({'result': 'success','userinfo':userinfo })

@app.route('/api/search', methods=['GET'])
def search_info():

   userinfo = list(db.user.find({}, {'_id':0}))
   return jsonify({'result':'success', 'userinfo': userinfo})

@app.route('/api/update', methods=['GET','POST'])
def update_info():
   
   if request.method == 'GET':
      token_receive = request.headers['token_give']

      try:
         # token을 시크릿키로 디코딩합니다.
         # 보실 수 있도록 payload를 print 해두었습니다. 우리가 로그인 시 넣은 그 payload와 같은 것이 나옵니다.
         payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
         print(payload)

         # payload 안에 id가 들어있습니다. 이 id로 유저정보를 찾습니다.
         # 여기에선 그 예로 닉네임을 보내주겠습니다.
         return jsonify({'result': 'success','id':payload['id']})
      except jwt.ExpiredSignatureError:
         # 위를 실행했는데 만료시간이 지났으면 에러가 납니다.
         return jsonify({'result': 'fail', 'msg':'로그인 시간이 만료되었습니다.'})

   if request.method == 'POST':
      id_receive = request.form['id_give']
      laptop_os_receive = request.form['laptop_os_give']
      laptop_receive = request.form['laptop_give']
      cellphone_os_receive = request.form['cellphone_os_give']
      cellphone_receive = request.form['cellphone_give']
      keyboard_receive = request.form['keyboard_give']
      mouse_receive = request.form['mouse_give']
   
   if db.user.find_one({'id': id_receive }):
      db.user.update_one({'id': id_receive },{'$set':{'laptop_os': laptop_os_receive, 'laptop': laptop_receive, 'cellphone_os': cellphone_os_receive, 'cellphone': cellphone_receive, 'keyboard': keyboard_receive, 'mouse': mouse_receive}})
      return jsonify({'result':'success'})
   return jsonify({'result':'fail', 'msg': '실패!'})

@app.route('/osPercentage', methods=['GET'])
def os_percentage():
    # Retrieve data from MongoDB
    users = db.user.find({})
    laptop_os_counts = {
        'WINDOW': 0,
        'MAC': 0,
        'others': 0
    }
    cellphone_os_counts = {
        'android': 0,
        'ios': 0,
        'others': 0
    }
    for user in users:
        laptop_os = user['laptop_os']
        cellphone_os = user['cellphone_os']
        laptop_os_counts[laptop_os] += 1
        cellphone_os_counts[cellphone_os] += 1
    
    # Calculate percentages
    Ltotal = sum(laptop_os_counts.values())
    Ctotal = sum(cellphone_os_counts.values())
    Lpercentages = {}
    Cpercentages = {}
    for os, count in laptop_os_counts.items():
        Lpercentages[os] = count / Ltotal * 100
    for os, count in cellphone_os_counts.items():
        Cpercentages[os] = count / Ctotal * 100
        
    return jsonify({'result': 'success','laptop_val':Lpercentages, 'cellphone_val':Cpercentages})

if __name__ == '__main__':
   app.run('0.0.0.0',port=5000,debug=True)