
var express = require('express');
var router = express.Router();
var passport = require('passport');
var mongoose = require('mongoose');
var User = mongoose.model('User');
var auth = require('./auth');


router.post('/register', function(req, res, next){
  if(!req.body.user.email || !req.body.user.password){
    return res.status(400).json({message: 'Please fill out all fields'});
  }

  User.findOne( { 'local.email': req.body.user.email }, function(err, user) {
    // console.log('user', user);
    if(err) { return next(err) };

    if(user) {
      return res.status(422).json({errors: {email: "alredy taken"}}); 
    };
  })

  var user = new User();

  user.local.name = req.body.user.username;
  
  user.local.email = req.body.user.email;

  user.local.password = user.setPassword(req.body.user.password)

  user.save().then(function (){
    // if(err){ return next(err); }
    return res.json({user: user.toAuthJSON()})
  }).catch(next);
});

router.post('/login', function(req, res, next){
  if(!req.body.user.email){
    return res.status(422).json({errors: {email: "can't be blank"}});
  }

  if(!req.body.user.password){
    return res.status(422).json({errors: {password: "can't be blank"}});
  }

  passport.authenticate('local', {session: false}, function(err, user, info){
    if(err){ return next(err); }

    if(user){
      // user.token = user.generateJWT();
      return res.json({user: user.toAuthJSON()});
    } else {
      return res.status(422).json(info);
    }
  })(req, res, next);
});

router.get('/user', auth.optional, function(req, res, next){
  // console.log('req', req.payload)
  User.findById(req.payload.id).then(function(user){
    if(!user){ return res.sendStatus(401); }

    // return res.json({user: user.toAuthJSON()});
    return res.json({user: user});
  }).catch(next);
});


router.get('/auth/google', 
  passport.authenticate('google', { scope: ['profile', 'email']}));

router.get('/auth/google/callback', function(req, res, next) {
  passport.authenticate('google', {session: false}, function(err, user, info) {
    if(err){ return next(err); }

    if(user){
      // console.log('google user', user);
      // user.token = user.generateJWT();
      // return res.json({user: user.toAuthJSON()});
      res.redirect('http://localhost:3001/pages/auth/login?token='+user.generateJWT('google'));
      // res.redirect('http://localhost:3001/pages/auth/login?token='+user.google.token);
      // return res.json({user: user.generateJWT('google')});
    } else {
      return res.status(422).json(info);
    }

  })(req, res, next);
});

module.exports = router;
