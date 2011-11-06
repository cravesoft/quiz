const path = require('path')
    , express = require('express')
    , redis = require('redis')
    , lazy = require("lazy")
    , fs = require('fs')
    , app = module.exports = express.createServer()
    , port = process.env.PORT || 1337
    ;

/** Configuration */
app.configure(function() {
    this.set('views', path.join(__dirname, 'views'));
    this.set('view engine', 'ejs');
    this.use(express.static(path.join(__dirname, '/public')));
    // Allow parsing cookies from request headers
    this.use(express.cookieParser());
    // Session management
    // Internal session data storage engine, this is the default engine embedded with connect.
    // Much more can be found as external modules (Redis, Mongo, Mysql, file...). look at "npm search connect session store"
    this.sessionStore = new express.session.MemoryStore({ reapInterval: 60000 * 10 });
    this.use(express.session({
        // Private crypting key
        "secret": "some private string",
        "store": this.sessionStore
    }));
    // Allow parsing form data
    this.use(express.bodyParser());
    //Redis config settings
    this.redisHost = '';
    this.redisPort = 0000;
    this.redisPass = '';
    this.redisChannel = 'test.data';
});
app.configure('development', function(){
    this.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});
app.configure('production', function(){
    this.use(express.errorHandler());
});

/** Middleware for limited access */
function requireLogin (req, res, next) {
  if (req.session.username) {
    // User is authenticated, let him in
    next();
  } else {
    // Otherwise, we redirect him to login form
    res.redirect("/login");
  }
}

accentsTidy = function(s) {
    var r=s.toLowerCase();
    r = r.replace(new RegExp("\\s", 'g'),"");
    r = r.replace(new RegExp("[àáâãäå]", 'g'),"a");
    r = r.replace(new RegExp("æ", 'g'),"ae");
    r = r.replace(new RegExp("ç", 'g'),"c");
    r = r.replace(new RegExp("[èéêë]", 'g'),"e");
    r = r.replace(new RegExp("[ìíîï]", 'g'),"i");
    r = r.replace(new RegExp("ñ", 'g'),"n");                            
    r = r.replace(new RegExp("[òóôõö]", 'g'),"o");
    r = r.replace(new RegExp("œ", 'g'),"oe");
    r = r.replace(new RegExp("[ùúûü]", 'g'),"u");
    r = r.replace(new RegExp("[ýÿ]", 'g'),"y");
    r = r.replace(new RegExp("\\W", 'g'),"");
    return r;
};

/** Routes */

/** Home page (requires authentication) */
app.get('/', [requireLogin], function (req, res, next) {
  res.render('index', { "username": req.session.username });
});

app.get('/session-index', function (req, res, next) {
    // Increment "index" in session
    req.session.index = (req.session.index || 0) + 1;
    // View "session-index.ejs"
    res.render('session-index', {
        "index":  req.session.index,
        "sessId": req.sessionID
    });
});

/** Login form */
app.get("/login", function (req, res) {
    // Show form, default value = current username
    res.render("login", { "username": req.session.username, "error": null });
});
app.post("/login", function (req, res) {
    var options = { "username": req.body.username, "error": null };
    if (!req.body.username) {
        options.error = "User name is required";
        res.render("login", options);
    } else if (req.body.username == req.session.username) {
        // User has not changed username, accept it as-is
        res.redirect("/");
    } else if (!req.body.username.match(/^[a-zA-Z0-9\-_]{3,}$/)) {
        options.error = "User name must have at least 3 alphanumeric characters";
        res.render("login", options);
    } else {
        // Validate if username is free
        req.sessionStore.all(function (err, sessions) {
            if (!err) {
                var found = false;
                for (var i=0; i<sessions.length; i++) {
                    var session = JSON.parse(sessions[i]); // Si les sessions sont stockées en JSON
                    if (session.username == req.body.username) {
                        err = "User name already used by someone else";
                        found = true;
                        break;
                    }
                }
            }
            if (err) {
                options.error = ""+err;
                res.render("login", options);
            } else {
                req.session.username = req.body.username;
                res.redirect("/");
            }
        });
    }
});

/** WebSocket */
var sockets = require('socket.io').listen(app).of('/chat');
const parseCookie = require('connect').utils.parseCookie;
sockets.authorization(function (handshakeData, callback) {
  // Read cookies from handshake headers
  var cookies = parseCookie(handshakeData.headers.cookie);
  // We're now able to retrieve session ID
  var sessionID = cookies['connect.sid'];
  // No session? Refuse connection
  if (!sessionID) {
    callback('No session', false);
  } else {
    // Store session ID in handshake data, we'll use it later to associate
    // session with open sockets
    handshakeData.sessionID = sessionID;
    // On récupère la session utilisateur, et on en extrait son username
    app.sessionStore.get(sessionID, function (err, session) {
      if (!err && session && session.username) {
        // On stocke ce username dans les données de l'authentification, pour réutilisation directe plus tard
        handshakeData.username = session.username;
        // OK, on accepte la connexion
        callback(null, true);
      } else {
        // Session incomplète, ou non trouvée
        callback(err || 'User not authenticated', false);
      }
    });
  }
});

var answer;
var question;
var numQuestions = 0;
var started = false;
var paused = false;
var pushed = {};
var points = {};
var usernames = {};
var timeoutID = 0;
const maxTime = 30000;

// Active sockets by session
var connections = {};
sockets.on('connection', function (socket) { // New client
    var sessionID = socket.handshake.sessionID; // Store session ID from handshake
    // this is required if we want to access this data when user leaves, as handshake is
    // not available in "disconnect" event.
    var username = socket.handshake.username; // Same here, to allow event "bye" with username
    if ('undefined' == typeof connections[sessionID]) {
        connections[sessionID] = { "length": 0 };
    // First connection
    sockets.emit('join', username, Date.now());
    }
    // Add connection to pool
    connections[sessionID][socket.id] = socket;
    connections[sessionID].length ++;
    // Create a Redis client and subscribe
    var redisClient = redis.createClient();
    redisClient.on("error", function (err) {
        console.log("Error " + err);
    });
    redisClient.flushdb();

    if ('undefined' == typeof pushed[sessionID]) {
        pushed[sessionID] = { "length": 0 };
    }
    pushed[sessionID] = false;
    pushed[sessionID].length ++;

    if ('undefined' == typeof usernames[sessionID]) {
        usernames[sessionID] = { "length": 0 };
    }
    usernames[sessionID] = username;
    usernames[sessionID].length ++;

    if ('undefined' == typeof points[sessionID]) {
        points[sessionID] = { "length": 0 };
    }
    points[sessionID] = 0;
    points[sessionID].length ++;

    // Read questions in file
    var i = 0;
    new lazy(fs.createReadStream('./docs/9100994lnbgxs.txt'))
    .lines
    .forEach(function(line) {
        i++;
        if (i%2 == 0) {
            redisClient.get("next.question.id", function (err, id) {
                redisClient.set("question:"+id+":answer", (line.toString()));
                redisClient.lpush("submitted.questions", id);
                numQuestions = id;
            });
        } else {
            redisClient.incr("next.question.id");
            redisClient.get("next.question.id", function (err, id) {
                redisClient.set("question:"+id+":question", (line.toString()));
            });
        }
    });

    // When user leaves
    socket.on('disconnect', function () {
        // Is this socket associated to user session ?
        var userConnections = connections[sessionID];
        if (userConnections.length && userConnections[socket.id]) {
            // Forget this socket
            userConnections.length --;
            delete userConnections[socket.id];
        }
        if (userConnections.length == 0) {
            // No more active sockets for this user: say bye
            sockets.emit('bye', username, Date.now());
        }
    });

    function emitTooLate() {
        sockets.emit('message', 'quiz', 'too late!', Date.now());
        sockets.emit('message', 'quiz', "the correct answer was '"+answer+"'", Date.now());
        emitQuestion();
    }

    function emitQuestion() {
        clearTimeout(timeoutID);
        id = Math.floor(Math.random()*numQuestions);
        console.log(id);
        console.log(numQuestions);
        for (var i=0; i<pushed.length; i++) {
            pushed[i] = false;
        }
        sockets.emit('release');
        redisClient.get("question:"+id+":answer", function (err, line) {
            answer = line.toString();
        });
        redisClient.get("question:"+id+":question", function (err, line) {
            question = line.toString();
            sockets.emit('message', 'quiz', question, Date.now());
        });
        timeoutID = setTimeout(emitTooLate, maxTime);
    }

    // New message from client = "write" event
    socket.on('write', function (message) {
        if (message[0] != '/') {
            sockets.emit('message', username, message, Date.now());
            if (started == true && paused == false) {
                var tokens = answer.split(' ou ');
                for (var i=0; i<tokens.length; i++) {
                    if (accentsTidy(tokens[i].toLowerCase()) == accentsTidy(message.toLowerCase())) {
                        sockets.emit('message', 'quiz', 'correct answer', Date.now());
                        points[sessionID] ++;
                        emitQuestion();
                        return;
                    }
                }
                sockets.emit('message', 'quiz', 'wrong answer', Date.now());
                points[sessionID] --;
                pushed[sessionID] = true;
            }
        } else {
            // User command
            command = message.substr(1);
            switch (command) {
                case 'help':
                    sockets.emit('message', 'quiz', 'start  pause  resume stop  ', Date.now());
                    sockets.emit('message', 'quiz', 'score  scores flip   sup   ', Date.now());
                    sockets.emit('message', 'quiz', 'help   skip                ', Date.now());
                    break;
                case 'flip':
                    sockets.emit('message', username, '（╯°□°）╯︵ ┻━┻', Date.now());
                    break;
                case 'sup':
                    sockets.emit('message', username, '¯\\_(ツ)_/¯', Date.now());
                    break;
                case 'pause':
                    if (started == true && paused == false) {
                        sockets.emit('message', username, 'paused the game', Date.now());
                        clearTimeout(timeoutID);
                        paused = true;
                    }
                    break;
                case 'resume':
                    if (started == true && paused == true) {
                        sockets.emit('message', username, 'resumed the game', Date.now());
                        timeoutID = setTimeout(emitTooLate, maxTime);
                        paused = false;
                    }
                    break;
                case 'start':
                    sockets.emit('message', username, 'started a new game', Date.now());
                    for (var i=0; i<points.length; i++) {
                        points[i] = 0;
                    }
                    emitQuestion();
                    started = true;
                    break;
                case 'stop':
                    if (started == true) {
                        sockets.emit('message', username, 'ended the game', Date.now());
                        started = false;
                    }
                    break;
                case 'skip':
                    if (started == true && paused == false) {
                        sockets.emit('message', username, 'skipped this question', Date.now());
                        emitQuestion();
                    }
                    break;
                case 'score':
                    if (points[sessionID] > 1) {
                        sockets.emit('message', username, 'has '+points[sessionID]+' points', Date.now());
                    } else {
                        sockets.emit('message', username, 'has '+points[sessionID]+' point', Date.now());
                    }
                    break;
                case 'scores':
                    for (var i=0; i<points.length; i++) {
                        sockets.emit('message', usernames[i], 'has '+points[i]+' points', Date.now());
                    }
                    break;
            }
        }
    });

    // New action from client = "push" event
    socket.on('push', function () {
        sockets.emit('push', username, Date.now());
    });
});

/** Start server */
if (!module.parent) {
    app.listen(port)
}
 
