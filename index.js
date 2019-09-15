const http = require('http');
require('dotenv').config()
const bcrypt = require('bcrypt')
const qs = require('querystring')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const User = require('./models/user')

mongoose.connect(process.env.MONGODB_URL, { useNewUrlParser: true})
  .then(() => {
    console.log('Connected to mongo db')
  })
  .catch(error => {
    console.error('error connecting to MONGODB', error.message)
  }
);

const server = http.createServer((request, response) => {
  const method = request.method;
  const pathname = request.url;

  if (method === 'POST') {
    //handle 
    if (pathname === '/login') {
      let chunks = [];
      request.on('data', (data) => {
        chunks.push(data);
      }).on('end', () => {
        chunks = JSON.parse(chunks)
        
        const email = chunks.email
        const password = chunks.password

        let passwordCorrect = false;
        try {
          User.findOne({ email: chunks.email}).then(user => {
            if (user) {
              bcrypt.compare(password, user.passwordHash).then((result) => {
                console.log(result)
                passwordCorrect = result

                const userToken = {
                  email: user.email,
                  id: user.id
                };
                const token = jwt.sign(userToken, process.env.SECRET)
                response.write({ token, email: user.email }.toString())
                response.end()

              }).catch(error => {
                response.write(error.toString())
                response.end()
              }) 
            }
            
            else if (!(user && passwordCorrect)) {
              return response.write({
                error: 'invalid username or password'
              }).stringify()
            }
            
          })
        } catch (error) {
          response.write({ message: "no user found"})
          response.end()
        }
        
      });
      
    } else if (pathname === '/signup') {
      let chunks = [];
      request.on('data', (data) => {
        chunks.push(data);
      }).on('end', () => {
        chunks = JSON.parse(chunks)
        
        const email = chunks.email
        const password = chunks.password
        const saltRounds = 10
        try {
          bcrypt.hash(password, saltRounds).then (passwordHash => {
            const user = new User ({
              email,
              passwordHash
            })
            user.save().then(savedUser => {
              //console.log(savedUser.toJSON())
              response.write(savedUser.toJSON().stringify())
              response.end()
            }).catch(error => {
              response.write(error.toString())
            }) 
                     
          }).catch (error => response.end(error))
        } catch (error) {
          response.write({ message: "error creating user" }.toString())
        }
        
      });
      
    }
  } else {
    response.write("HNGi6: No endpoint")
    response.end();
  }
});

server.listen(3000)