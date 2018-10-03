var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var db = require('../database/db');
var bcrypt = require('bcryptjs');
const saltRounds = 11; 

var data;


// var User = require('../models/user');

// Register
router.get('/register', function (req, res) {
	res.render('register');
});

// Login
router.get('/login', function (req, res) {
	res.render('login');
});

// Webstore
router.get('/webstore', function(req, res) {
	res.render('webstore');
});
router.get('/clear', function(req, res){
	cart_data = req.session.cart = {};
	db.connection.getConnection(function(err, connection){
		connection.query('SELECT `product_id`,`title`,`description` FROM `products`', function(err, rows, fields){
			if (err) throw err;
			var error_msg = "You've flushed your cart!";
			res.render('webstore', {rows:rows, error_msg});
		})
	})
})
var cart_data, cart = {};

router.post('/addToCart', function(req, res){
	db.connection.getConnection(function(err, connection){
		connection.query('SELECT `product_id`,`title`,`description` FROM `products`', function(err, rows, fields){
		if (err) throw err;
		cart = req.session.cart;
		if (!cart) {
			cart = req.session.cart = {}
		}
	
		var id = req.body.id;
		var count = parseInt(req.body.count, 10);

		cart[id] = (cart[id] || 0) + count;

		var ids = Object.keys(cart);
		if (ids.length > 0) {
			connection.query('SELECT * FROM products WHERE product_id IN (' + ids + ')', function (err, result) {
				if (err) throw err;
				cart_data = result;
				res.render('webstore', {rows: rows, data: data, cart_data: result, cart: cart});
			});
		} else {
			res.render('webstore', {rows: rows, data: data, cart_data: cart_data});
		}
	});
	});
});
// Register User
router.post('/register', function (req, res) {
	var userData = { 
	 'user_id': null,
	 'firstname': req.body.firstname,
	 'prefix': req.body.prefix,
	 'lastname': req.body.lastname,
	 'email': req.body.email,
	 'password': req.body.password,
	 'address' : req.body.address,
	 'number' : req.body.number,
	 'addition' : req.body.additon,
	 'postal' : req.body.postal,
	 'city' : req.body.city,
	 'country' : req.body.country,
	 'telephone' : req.body.telephone,
	 'role' : 'user'
	}

	// Validation
	req.checkBody('firstname', 'Name is required').notEmpty();
	// req.checkBody('prefix', '').notEmpty();
	req.checkBody('lastname', 'Last name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);
	req.checkBody('address', 'Address is required').notEmpty();
	req.checkBody('number', 'A number is required').notEmpty();
	// req.checkBody('addition', '').notEmpty();
	req.checkBody('postal', 'Postal is required').notEmpty();
	req.checkBody('city', 'Country is required').notEmpty();
	req.checkBody('telephone', 'A telephone number is required').notEmpty();

	var errors = req.validationErrors();

	if (errors) {
		res.render('register', {
			errors: errors
		});
	}
	else {
		//checking for email and telephone number if they are already taken
		db.connection.getConnection(function(err, connection){
			if (err) throw err 
				
			else{
				// Checkt of de telephone number al bestaat in de database
				connection.query('SELECT `telephone` FROM `users` WHERE telephone = "' + userData['telephone'] + '" ', function(err, rows, fields){
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
						req.flash('error_msg', 'Your given phonenumber is already in use, please try another one');
						res.redirect('/users/register');
					}
				});
			}
		});
	}
});
// The login 
passport.use('local-login', new LocalStrategy({

	usernameField: 'email',
  
	passwordField: 'password',
  
	passReqToCallback: true //passback entire req to call back
  } , function (req, email, password, done){
		if(!email || !password ){ 
			return done(null, false, req.flash('error_msg','All fields are required.')); 
		}
		db.connection.getConnection(function(err, connection){
			connection.query("select * from users where email = ?", [email], function(err, rows){
	
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
	done(null, user.user_id);
});

passport.deserializeUser(function(user_id, done){
	db.connection.getConnection(function(err, connection){
		connection.query("select * from users where user_id = "+ user_id, function (err, rows){
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
	req.session.destroy();

	res.redirect('/users/login');
});

module.exports = router;