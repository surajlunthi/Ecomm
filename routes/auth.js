const express = require('express');
const {check,validationResult} = require('express-validator')
const authController = require('../controllers/auth');
const User = require('../models/user')


const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login', authController.postLogin);

router.post('/signup', check('email').isEmail()
.withMessage('Not valid Email')
.custom((value,{req})=>{
    
    return User.findOne({ email: value })
    .then(userDoc => {
      if (userDoc) {
        return Promise.reject('Email already Exists ,Pick different one')
      }

})
}),
check('password').isLength({min:8}).withMessage('Not Valid Password')
,check('confirmPassword')
.custom((value,{req})=>{
    if(value !== req.body.password){
throw new Error ('Passwords do not match')
}
return true;
}),
authController.postSignup);

router.post('/logout', authController.postLogout);

router.get('/reset',authController.getReset)

router.post('/reset',authController.postReset)  

router.get('/reset/:token',authController.getNewPassword)

router.post('/new-password',authController.postNewPassword)

module.exports = router;