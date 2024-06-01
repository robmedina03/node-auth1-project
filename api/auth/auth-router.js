// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const bcrypt = require('bcrypt')
const Users = require('../users/users-model')
const{
  checkUsernameFree,
  checkPasswordLength,
  checkUsernameExists
} = require('./auth-middleware')

const router = express.Router()


router.post('/register', checkUsernameFree, checkPasswordLength, async (req,res,next) => {
  try{
    const{username, password} = req.body;
    const hash = bcrypt.hashSync(password,8)
    const newUser= {username, password: hash};
    const user = await Users.add(newUser);
    res.status(201).json(user)
  }catch(err){
    next(err)
  }
})

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try{
    const {password} = req.body;
    if(bcrypt.compareSync(password, req.user.password)){
      req.session.user = req.user;
      res.status(200).json({message:`Welcome ${req.user.username}!`})
    }else{
      res.status(401).json({message:'Invalid credentials'})
    }
  }catch(err){
    next(err)
  }
})

router.get('/logout', (req,res) => {
  if(req.session && req.session.user){
    req.session.destroy(err => {
      if(err) {
        res.status(500).json({message: 'we could not log you out, try again'})
      }else {
        res.status(200).json({message:'logged out'})
      }
    })
    }else{
      res.status(200).json({message: 'no session'})
    }
  
})

module.exports = router

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
