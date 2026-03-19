var db = require('../models')
var bCrypt = require('bcrypt')
const { execFile } = require('child_process');
var mathjs = require('mathjs')
var libxmljs = require("libxmljs");
var serialize = require("node-serialize")
const Op = db.Sequelize.Op

function isValidHost(host) {
  if (!host || typeof host !== 'string') return false
  host = host.trim()
  // IPv4
  var ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
  if (ipv4.test(host)) {
    return host.split('.').every(o => parseInt(o,10) >= 0 && parseInt(o,10) <= 255)
  }
  // Simple hostname validation (letters, digits, hyphen, dot)
  var hostname = /^[a-zA-Z0-9.-]+$/
  return hostname.test(host) && host.length <= 253
}

module.exports.userSearch = function (req, res) {
  var login = (req.body && req.body.login) ? req.body.login.toString() : ''
  if (!login) {
    req.flash('warning', 'User not found')
    return res.render('app/usersearch', { output: null })
  }

  // Use Sequelize model to avoid manual SQL concatenation
  db.User.findOne({
    where: { login: login },
    attributes: ['name','id']
  }).then(user => {
    if (user) {
      var output = { user: { name: user.name, id: user.id } }
      res.render('app/usersearch', { output: output })
    } else {
      req.flash('warning', 'User not found')
      res.render('app/usersearch', { output: null })
    }
  }).catch(err => {
    req.flash('danger', 'Internal Error')
    res.render('app/usersearch', { output: null })
  })
}

module.exports.ping = function (req, res) {
  const address = (req.body && req.body.address) ? req.body.address.toString().trim() : ''
  if (!isValidHost(address)) {
    req.flash('warning', 'Invalid address')
    return res.render('app/ping', { output: 'Invalid address' })
  }
  const safeEnv = Object.assign({}, process.env)
  safeEnv.PATH = '/usr/bin:/bin'
  // use absolute ping path and sanitized env to avoid executing unexpected binaries
  execFile('/bin/ping', ['-c','2', address], { env: safeEnv, windowsHide: true }, function (err, stdout, stderr) {
    var output = ''
    if (err && err.code !== 0) {
      output = (stdout || '') + (stderr || '') + '\nError: ' + (err.message || '')
    } else {
      output = (stdout || '') + (stderr || '')
    }
    res.render('app/ping', { output: output })
  })
}

module.exports.listProducts = function (req, res) {
  db.Product.findAll().then(products => {
    output = { products: products }
    res.render('app/products', { output: output })
  })
}

module.exports.productSearch = function (req, res) {
  db.Product.findAll({
    where: {
      name: {
        [Op.like]: '%' + req.body.name + '%'
      }
    }
  }).then(products => {
    output = { products: products, searchTerm: req.body.name }
    res.render('app/products', { output: output })
  })
}

module.exports.modifyProduct = function (req, res) {
  if (!req.query.id || req.query.id == '') {
    output = { product: {} }
    res.render('app/modifyproduct', { output: output })
  } else {
    db.Product.find({
      where: { 'id': req.query.id }
    }).then(product => {
      if (!product) { product = {} }
      output = { product: product }
      res.render('app/modifyproduct', { output: output })
    })
  }
}

module.exports.modifyProductSubmit = function (req, res) {
  if (!req.body.id || req.body.id == '') { req.body.id = 0 }
  db.Product.find({
    where: { 'id': req.body.id }
  }).then(product => {
    if (!product) { product = new db.Product() }
    product.code = req.body.code
    product.name = req.body.name
    product.description = req.body.description
    product.tags = req.body.tags
    product.save().then(p => {
      if (p) {
        req.flash('success', 'Product added/modified!')
        res.redirect('/app/products')
      }
    }).catch(err => {
      output = { product: product }
      req.flash('danger', err)
      res.render('app/modifyproduct', { output: output })
    })
  })
}

module.exports.userEdit = function (req, res) {
  res.render('app/useredit', {
    userId: req.user.id,
    userEmail: req.user.email,
    userName: req.user.name
  })
}

module.exports.userEditSubmit = function (req, res) {
  db.User.find({
    where: { 'id': req.body.id }
  }).then(user =>{
    if(req.body.password && req.body.password.length>0){
      if (req.body.password == req.body.cpassword) {
        user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
      } else {
        req.flash('warning', 'Passwords dont match')
        res.render('app/useredit', {
          userId: req.user.id,
          userEmail: req.user.email,
          userName: req.user.name,
        })
        return
      }
    }
    user.email = req.body.email
    user.name = req.body.name
    user.save().then(function () {
      req.flash('success',"Updated successfully")
      res.render('app/useredit', {
        userId: req.body.id,
        userEmail: req.body.email,
        userName: req.body.name,
      })
    })
  })
}

module.exports.redirect = function (req, res) {
  var url = req.query && req.query.url ? req.query.url.toString() : ''
  // Allow only a small whitelist of internal paths to avoid open redirect
  const allowedRedirects = [
    '/',
    '/app/products',
    '/app/login',
    '/app/useredit',
    '/app/ping'
  ]
  if (url && allowedRedirects.includes(url)) {
    res.redirect(url)
  } else {
    res.send('invalid redirect url')
  }
}

module.exports.calc = function (req, res) {
  if (req.body.eqn) {
    var eqn = req.body.eqn.toString()
    // allow only digits, operators, parentheses, whitespace, comma, dot, ^, %
    if (/^[0-9+\-*/%^().,\s]+$/.test(eqn)) {
      try {
        var result = mathjs.evaluate(eqn)
        res.render('app/calc', { output: result })
      } catch (e) {
        res.render('app/calc', { output: 'Invalid math expression' })
      }
    } else {
      res.render('app/calc', { output: 'Invalid characters in expression' })
    }
  } else {
    res.render('app/calc', { output: 'Enter a valid math string like (3+3)*2' })
  }
}

module.exports.listUsersAPI = function (req, res) {
  db.User.findAll({}).then(users => {
    res.status(200).json({ success: true, users: users })
  })
}

module.exports.bulkProductsLegacy = function (req,res){
  // TODO: Deprecate this soon
  if(req.files.products){
    var products = serialize.unserialize(req.files.products.data.toString('utf8'))
    products.forEach( function (product) {
      var newProduct = new db.Product()
      newProduct.name = product.name
      newProduct.code = product.code
      newProduct.tags = product.tags
      newProduct.description = product.description
      newProduct.save()
    })
    res.redirect('/app/products')
  }else{
    res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:true})
  }
}

module.exports.bulkProducts =  function(req, res) {
  if (req.files.products && req.files.products.mimetype=='text/xml'){
    try {
      // disable entity expansion: remove noent:true
      var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), { noblanks:true })
      products.root().childNodes().forEach( product => {
        var newProduct = new db.Product()
        newProduct.name = product.childNodes()[0].text()
        newProduct.code = product.childNodes()[1].text()
        newProduct.tags = product.childNodes()[2].text()
        newProduct.description = product.childNodes()[3].text()
        newProduct.save()
      })
      res.redirect('/app/products')
    } catch (e) {
      res.render('app/bulkproducts',{messages:{danger:'Invalid XML file'},legacy:false})
    }
  }else{
    res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:false})
  }
}