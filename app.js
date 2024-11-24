var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const mongoose = require('mongoose');
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
const passport = require('passport');
const session = require('express-session');
var app = express();
require('dotenv').config();  // Carrega as variáveis de ambiente

require('./config/passport');  // Certifique-se de importar o arquivo onde você configurou o passport




app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Só usa 'secure' se estiver em produção (HTTPS)
    httpOnly: true,  // Impede que o cookie seja acessado via JavaScript
    maxAge: 1000 * 60 * 60 * 24 // 1 dia
  }
}));

// Inicializa o Passport e o session middleware
app.use(passport.initialize());
app.use(passport.session());

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json()); // Middleware para processar JSON
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Definindo as rotas
app.use('/', indexRouter);
app.use('/users', usersRouter);

// Adicionando a rota para o /auth
const authRoutes = require('./routes/auth');
app.use('/auth', authRoutes);  // Mantenha essa linha aqui apenas uma vez

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

// ----- Sequelize Connection -----
const sequelize = require('./config/db');
sequelize.sync().then(() => console.log('Database synchronized!'));

module.exports = app;
