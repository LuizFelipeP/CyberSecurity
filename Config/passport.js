const passport = require('passport');
const User = require('../models/user'); // Certifique-se de que o caminho para o seu modelo de usuário está correto
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();  // Carrega as variáveis de ambiente

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, function(accessToken, refreshToken, profile, done) {
    // Lógica de autenticação e armazenamento do usuário
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
                    password: '',  // Definindo uma senha vazia (não é obrigatória no seu caso)
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
    done(null, user.id); // Aqui você pode salvar o ID ou qualquer identificador único do usuário
});

// Desserializa o usuário a partir do ID da sessão
passport.deserializeUser((id, done) => {
    User.findByPk(id)  // Usando findByPk para buscar o usuário pelo ID
        .then(user => {
            done(null, user);
        })
        .catch(err => done(err));  // Em caso de erro na consulta
});
