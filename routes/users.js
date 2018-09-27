var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var db = require('../database/db');
var bcrypt = require('bcryptjs');
const saltRounds = 11;

// var User = require('../models/user');

// Register
router.get('/register', function (req, res) {
	res.render('register');
});

// Login
router.get('/login', function (req, res) {
	res.render('login');
});

// Register User
router.post('/register', function (req, res) {
	var userData = { 
	 'id': null,
	 'username': req.body.username,
	 'password': req.body.password,
	 'name': req.body.name,
	 'email': req.body.email
	}

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if (errors) {
		res.render('register', {
			errors: errors
		});
	}
	else {
		//checking for email and username are already taken
		db.connection.getConnection(function(err, connection){
			if (err) throw err 
				
			else{
				// Checkt of de username al bestaat in de database
				connection.query('SELECT `username` FROM `users` WHERE username = "' + userData['username'] + '" ', function(err, rows, fields){
					if (err) throw err;
					// Checkt of de terugkomende object leeg is, dan bestaat de user nog niet
					else if (!rows.length){
						// Checkt of de email al bestaat in database
						connection.query('SELECT `email` FROM `users` WHERE email = "' + userData['email'] + '" ', function(err, result, fields){
							if (err) throw err;
							
							else if (!result.length){
								//hashed het wachtwoord en zet alle ingevoerde data in de database door middel van een object (userData)
								bcrypt.genSalt(saltRounds, function(err, salt) {
									bcrypt.hash(userData['password'], salt, function(err, hash) {
										userData.password = hash;
										connection.query('INSERT INTO users SET ?', userData ,function(err, results, fields){
											if (err) throw err; 
											else {
												//Cut de connectie om sql injecties te voorkomen en stuurt je naar de loginpagina
												connection.release();
												req.flash('success_msg', 'You are successfully registered! You can now log in');
												res.redirect('/users/login');
											}
										});
									});
								});
							}
							//Het terugkomende object heeft inhoud dus bestaat de email al in de database
							else if(result.length){
								req.flash('error_msg', 'Your chosen email already has an account, please try another one');
								res.redirect('/users/register');
						    }
						});
					//Het terugkomende object heeft inhoud dus bestaat de username al in de database
					} else if (rows.length){
						req.flash('error_msg', 'Your chosen username already exists, please try another one');
						res.redirect('/users/register');
					}
				});
			}
		});
	}
});
passport.use('local-login', new LocalStrategy({

	usernameField: 'username',
  
	passwordField: 'password',
  
	passReqToCallback: true //passback entire req to call back
  } , function (req, username, password, done){
		if(!username || !password ){ 
			return done(null, false, req.flash('error_msg','All fields are required.')); 
		}
		db.connection.getConnection(function(err, connection){
			connection.query("select * from users where username = ?", [username], function(err, rows){
	
			// console.log(rows);
	
			if (err) return done(req.flash('error_msg',err));
	
			if(!rows.length){ 
				return done(null, false, req.flash('error_msg','Invalid username or password.'), connection.release()); 
			}
				var hash = rows[0].password;
				var candidatePassword = password;
			bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
				if(err) throw err;
				if (isMatch){
					return done(null, rows[0], req.flash('success_msg', `You've been successfully logged in!`), connection.release());
				} else {
				return done(null, false, req.flash('error_msg','Invalid username or password.'), connection.release());
				}
			});  
		});
	});
}));

passport.serializeUser(function(user, done){
	done(null, user.id);
});

passport.deserializeUser(function(id, done){
	db.connection.getConnection(function(err, connection){
		connection.query("select * from users where id = "+ id, function (err, rows){
			done(err, rows[0], connection.release());
		});
	});
});

router.post('/login',
	passport.authenticate('local-login', { successRedirect: '/', failureRedirect: '/users/login', failureFlash: true }),
	function (req, res) {
		res.redirect('/');
	});

router.get('/logout', function (req, res) {
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});

module.exports = router;