const express = require('express')
const sqlite3 = require('sqlite3')
const session = require('express-session')
const { authenticator } = require('otplib')
const QRCode = require('qrcode')
const jwt = require('jsonwebtoken')
const expressJWT = require('express-jwt')
const bodyParser = require('body-parser')
const app = express()
const port = 3000
const request = require('request')

const eth_account = {
  address: '0x168a656d9b5DE39668Aa033f489FC4d6B7C35121',
  private_key: '0xce5a68c19394283644d2252714ca94046611f76ba3276e56441edbacb398d1f8'
}
app.set('view engine', 'ejs')

app.use(session({
  secret: 'supersecret',
}))


app.use(bodyParser.urlencoded({ extended: false }))

app.get('/', (req, res) => {
  res.render('signup.ejs')
})

app.post('/sign-up', (req, res) => {
  const email = req.body.email,
    secret = authenticator.generateSecret()
  const password = req.body.password

  const db = new sqlite3.Database('db.sqlite')
  const address = eth_account.address
  const private_key = eth_account.private_key
  db.serialize(() => {
    db.run('INSERT INTO `users`(`email`, `password`, `secret`, `address`) VALUES (?, ?, ?, ?)',
      [email, password, secret, address],
      (err) => {
        if (err) {
          throw err
        }

        //use an account
        //save it to vault
        var options = {
          method: 'POST',
          body: { data: {
            private_key: private_key
          }},
          json: true,
          url: 'http://127.0.0.1:8200/v1/secret/data/account',
          headers: {
            'X-Vault-Token':'hvs.AyQnViQje9gT6DRzi5f4MyEc'
          }
        };

        function callback(error, response, body) {
          if (!error && response.statusCode == 200) {
            console.log(body)

            //generate qr and put it in session
            QRCode.toDataURL(authenticator.keyuri(email, '2FA Node App', secret), (err, url) => {
              if (err) {
                throw err
              }

              req.session.qr = url
              req.session.email = email
              req.session.address = address
              res.redirect('/sign-up-2fa')
            })

          }
        }

        request(options, callback)

        
      })
  })
})

app.get('/sign-up-2fa', (req, res) => {
  if (!req.session.qr) {
    return res.redirect('/')
  }

  return res.render('signup-2fa.ejs', { qr: req.session.qr, address: req.session.address })
})

app.post('/sign-up-2fa', (req, res) => {
  if (!req.session.email) {
    return res.redirect('/')
  }

  const email = req.session.email,
    code = req.body.code

  return verifyLogin(email, code, req, res, '/sign-up-2fa')
})

const jwtMiddleware = expressJWT({
  secret: 'supersecret',
  algorithms: ['HS256'],
  getToken: (req) => {
    return req.session.token
  }
})

app.get('/login', (req, res) => {
  return res.render('login.ejs')
})

app.post('/login', (req, res) => {
  //verify login
  const email = req.body.email,
    code = req.body.code

  return verifyLogin(email, code, req, res, '/login')
})

app.get('/private', jwtMiddleware, (req, res) => {
  return res.render('private.ejs', {email: req.user})
})

app.get('/logout', jwtMiddleware, (req, res) => {
  req.session.destroy()
  return res.redirect('/')
})

function verifyLogin (email, code, req, res, failUrl) {
  //load user by email
  const db = new sqlite3.Database('db.sqlite')
  db.serialize(() => {
    db.get('SELECT secret FROM users WHERE email = ?', [email], (err, row) => {
      if (err) {
        throw err
      }

      if (!row) {
        return res.redirect('/')
      }

      if (!authenticator.check(code, row.secret)) {
        //redirect back
        return res.redirect(failUrl)
      }

      //correct, add jwt to session
      req.session.qr = null
      req.session.email = null
      req.session.token = jwt.sign(email, 'supersecret')

      //redirect to "private" page
      return res.redirect('/private')
    })
  })
}

//create database with tables if it doesn't exist
const db = new sqlite3.Database('db.sqlite')
db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS `users` (`user_id` INTEGER PRIMARY KEY AUTOINCREMENT, `email` VARCHAR(255) NOT NULL, `password` VARCHAR(255), `secret` varchar(255) NOT NULL, `address` VARCHAR(255))')
})
db.close()

app.listen(port, () => {
  console.log(`2FA Node app listening at http://localhost:${port}`)
})