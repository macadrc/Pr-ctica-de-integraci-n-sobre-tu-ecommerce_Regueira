

const adminController = require('./controllers/adminController');
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors'); 
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const userSchema = new mongoose.Schema({
  first_name: String,
  last_name: String,
  email: { type: String, unique: true },
  age: Number,
  password: String,
  cart: { type: mongoose.Schema.Types.ObjectId, ref: 'Cart' },
  role: { type: String, default: 'user' },
});

userSchema.pre('save', async function (next) {
  const user = this;
  if (user.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(user.password, salt);
    user.password = hashedPassword;
  }
  next();
});

const User = mongoose.model('User', userSchema);


passport.use(new LocalStrategy(
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email });

      if (!user || !(await bcrypt.compare(password, user.password))) {
        return done(null, false, { message: 'Usuario o contraseña incorrectos' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));


passport.use(new GitHubStrategy({
  clientID: 'tuClientID',
  clientSecret: 'tuClientSecret',
  callbackURL: 'http://tu-app-url/auth/github/callback'
},
(accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}
));


const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'tu_secreto', 
};

passport.use(new JwtStrategy(jwtOptions, async (payload, done) => {
  try {
    const user = await User.findById(payload.id);

    if (user) {
      return done(null, user);
    } else {
      return done(null, false);
    }
  } catch (error) {
    return done(error, false);
  }
}));


app.use(session({
  secret: 'tu_secreto',
  resave: false,
  saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());
app.use(express.json());


app.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user) => {
    if (err || !user) {
      return res.status(401).json({ message: 'Autenticación fallida' });
    }

    const token = jwt.sign({ id: user._id }, 'tu_secreto', { expiresIn: '1h' });

    return res.json({ token });
  })(req, res, next);
});


app.get('/api/sessions/current', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.json(req.user);
});


mongoose.connect('mongodb+srv://<usuario>:<contraseña>@<cluster>/<base_de_datos>?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Error de conexión a MongoDB:'));
db.once('open', () => {
  console.log('Conexión exitosa a MongoDB');
});


const port = 8080;
server.listen(port, () => {
  console.log(`Servidor escuchando en el puerto ${port}`);
});
