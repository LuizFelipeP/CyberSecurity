const passport = require('passport');
const User = require('../models/user'); 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config(); 

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, function(accessToken, refreshToken, profile, done) {
    User.findOne({
        where: { googleId: profile.id }  // Buscando pelo googleId
    })
        .then(user => {
            if (!user) {
                // Criando um novo usuário se não encontrado
                user = new User({
                    googleId: profile.id,  // Armazenando o googleId
                    username: profile.displayName,
                    email: profile.emails[0].value,
                    photo: profile.photos[0].value,
                    password: '',  //
                });
                user.save()
                    .then(() => done(null, user))  // Usuário criado e salvo
                    .catch(err => done(err));  // Em caso de erro ao salvar o usuário
            } else {
                return done(null, user); // Usuário já existe
            }
        })
        .catch(err => done(err));  // Em caso de erro na consulta
}));

// Serializa o usuário para a sessão
passport.serializeUser((user, done) => {
    done(null, user.id); 
});

// Desserializa o usuário a partir do ID da sessão
passport.deserializeUser((id, done) => {
    User.findByPk(id) 
        .then(user => {
            done(null, user);
        })
        .catch(err => done(err));  
});
