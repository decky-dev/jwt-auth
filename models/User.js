var mongoose = require('mongoose');
var bcrypt   = require('bcrypt-nodejs');
var uniqueValidator = require('mongoose-unique-validator');
var jwt = require('jsonwebtoken');

var UserSchema = new mongoose.Schema({
	local: {
    // email: {type: String, lowercase: true, unique: true, required: [true, "can't be blank"], match: [/\S+@\S+\.\S+/, 'is invalid'], index: true},
		name: String,
    email: {type: String, lowercase: true, match: [/\S+@\S+\.\S+/, 'is invalid']},
		password: String
	},
  google: {
    id: String,
    token: String,
    name: String,
    email: String
  }
}, {timestamps: true});

// generating a hash
UserSchema.methods.setPassword = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// checking if password is valid
UserSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.local.password);
};


UserSchema.methods.generateJWT = function(loginType) {
  var today = new Date();
  var exp = new Date(today);
  exp.setDate(today.getDate() + 60);

  return jwt.sign({
    id: this._id,
    email: loginType === 'google' ? this.google.email : this.local.email,
    exp: parseInt(exp.getTime() / 1000),
  }, 'secret');
};

UserSchema.methods.toAuthJSON = function(){
  return {
    // email: this.local.email,
    token: this.generateJWT(),
  };
};


UserSchema.plugin(uniqueValidator, {message: 'is already taken.'});

module.exports = mongoose.model('User', UserSchema);