var passport = require('passport');
var mongoose = require('mongoose');
var User = mongoose.model('User');
var LocalStrategy = require('passport-local').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

var googleAuth = require('./google-auth');

passport.use(new LocalStrategy({
  usernameField: 'user[email]',
  passwordField: 'user[password]'
}, function(email, password, done) {
 
  User.findOne({'local.email': email}).then(function(user){
    if(!user || !user.validPassword(password)){
      return done(null, false, {errors: {'email or password': 'is invalid'}});
    }

    return done(null, user);

  }).catch(done);

}));

passport.use(new GoogleStrategy({
	clientID		    : googleAuth.clientID,
 	clientSecret    : googleAuth.clientSecret,
  callbackURL     : googleAuth.callbackURL,
}, function(token, refreshToken, profile, done){
	// console.log('token', token);
	console.log('profile', profile);
	process.nextTick(function() {
		User.findOne( {'google.id': profile.id }, function(err, user) {
			if(err)
				return done(err);
			if(user) {
				return done(null, user);
			}
			else {
				var newUser = new User();
				newUser.google.id    = profile.id;
				newUser.google.token = token;
				newUser.google.name  = profile.displayName;
				newUser.google.email = profile.emails[0].value;

				newUser.save(function(err) {
					if(err)
						throw err;
					return done(null, newUser);
				})
			}
		})
	})
}));


module.exports = passport;