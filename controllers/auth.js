const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer')
const sendinBlue = require('nodemailer-sendinblue-transport');
const crypto = require('crypto')
const {validationResult} =require('express-validator')

const User = require('../models/user');

const transporter = nodemailer.createTransport({
  service: 'SendinBlue', // no need to set host or port etc.
  auth: {
      user: 'whoissurajlunthi@gmail.com',
      pass: 'xjT5VkUr3EBq9L76'
  }
});

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput:{
     email:""
    }
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        req.flash('error', 'Invalid email or password.');
        return res.redirect('/login');
      }
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }
          req.flash('error', 'Invalid email or password.');
          res.redirect('/login');
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch(err => {
      const error =  new Error(err)
      error.httpStatusCode = 500;
      return next (error)
    });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  const Errors = validationResult(req)
  if(!Errors.isEmpty())
  {
    console.log(Errors.array())
    return res.render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: Errors.array()[0].msg,
      oldInput:{
        email:email,
        password:password,
        confirmPassword:req.body.confirmPassword}
    });
  } bcrypt
        .hash(password, 12)
        .then(hashedPassword => {
          const user = new User({
            email: email,
            password: hashedPassword,
            cart: { items: [] }
          });
          return user.save();
        })
        .then(result => {
          res.redirect('/login');
          transporter.sendMail({
            to:email,
            from:'whoissurajlunthi@gmail.com',
            subject:' signed up',
            html:'<h1> You signed up </h>'
          })
        })
        .catch(err=>{
          console.log(err)
        })
        .catch(err => {
          const error =  new Error(err)
          error.httpStatusCode = 500;
          return next (error)
        });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};
exports.getReset = (req,res) =>{
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message
  });
}
exports.postReset = (req,res)=>{

  crypto.randomBytes(32,(err,buffer)=>{
    if(err)
    {
      console.log(err)
      return res.redirect('/reset')
    }
    const token = buffer.toString('hex')

    User.findOne({email: req.body.email})
    .then((user)=>{
 
      if(!user)
      {
        req.flash('error','No Account Found')
        return res.redirect('/reset');
      }
      user.resetToken = token;
      user.resetTokenExpirationDate = Date.now()+ 3600000; 
      return user.save()
    })
    .then(result =>{
      res.redirect('/')
      transporter.sendMail({
        to:req.body.email,
        from:'whoissurajlunthi@gmail.com',
        subject:'Password Reset',
        html:`
        <p> You Requested a Password Reset </p>
        <p>  <a href = "http://localhost:3000/reset/${token}"> Click this Link </a>to Change Password </p>
        <p> This Link will be valid for 1 hour </p> `
      })
    })
    .catch(err => {
      const error =  new Error(err)
      error.httpStatusCode = 500;
      return next (error)
    });
   
  })

}
exports.getNewPassword = (req,res)=>{ 

  const token = req.params.token
 

  User.findOne({resetToken:token, resetTokenExpirationDate :{$gt: Date.now()}})
  .then(user =>{ 

    let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  
  res.render('auth/new-password', {
    path: '/new-password',
    pageTitle: 'Reset Password',
    errorMessage: message,
    passwordToken: token,
    userId:user._id.toString()

  })
})
.catch(err => {
  const error =  new Error(err)
  error.httpStatusCode = 500;
  return next (error)
});
  
}
exports.postNewPassword = (req,res) =>{

  const newPassword = req.body.password
  const userId = req.body.userId
  const passwordToken = req.body.passwordToken
  let resetUser


  User.findOne({
    resetToken:passwordToken,
    resetTokenExpirationDate: {$gt:Date.now()},
    _id:userId
  })
  .then( user =>{
    resetUser = user
    return bcrypt.hash(newPassword,12)}
 )
 .then(hashedPassword =>{
   resetUser.password = hashedPassword,
   resetUser.resetToken = null
   resetUser.resetTokenExpirationDate = undefined

    return resetUser.save()
 })
 .then((result)=>
 {
   res.redirect('/login')
 })
 .catch(err => {
  const error =  new Error(err)
  error.httpStatusCode = 500;
  return next (error)
});

}