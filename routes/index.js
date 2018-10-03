var express = require('express');
var router = express.Router();
var db = require('../database/db');
var exphbs = require('express-handlebars');

// var cart_data, cart = {};
var data;


// Check if logged in, Get Homepage
router.get('/', ensureAuthenticated, function(req, res){
	res.render('index');
});

// Check if logged in, Get webstore
router.get('/users/webstore', ensureAuthenticated, function(req, res){
	db.connection.getConnection(function(err, connection){
		if (err) throw err;
		var cart = req.session.cart;
		connection.query('SELECT `product_id`,`title`,`description` FROM `products`', function(err, rows, fields){
			if (err) throw err;
			if (cart) {
				var ids = Object.keys(cart);
				connection.query('SELECT * FROM `products` WHERE `product_id` IN (' + ids + ')', function (err, result) {
					if (err) throw err;
					cart_data = result;
					res.render('webstore', {rows: rows, data: data, cart_data: result, cart: cart});
				});
			} else {
				res.render('webstore', {rows: rows});
			}
		});
	});
});

function ensureAuthenticated(req, res, next){
	if(req.isAuthenticated()){
		return next();
	} else {
		res.redirect('/users/login');
	}
}
module.exports = router;
