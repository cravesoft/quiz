const path = require('path')
    , express = require('express')
    , redis = require('redis')
    , lazy = require("lazy")
    , fs = require('fs')
    , app = module.exports = express.createServer()
    , port = process.env.PORT || 1337
    ;

var password = "admin";
var started = false;
var paused = false;
var timeoutID = 0;
var question = "";
var answer = "";
const maxTime = 30000;

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
    this.redisChannel = 'quiz.data';
    // Create a Redis client and subscribe
    var redisClient;
    redisClient = redis.createClient();
    redisClient.on("error", function (err) {
        console.log("Error " + err);
    });
    redisClient.flushdb();
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

tidyAccents = function(s) {
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
  res.render('index', { "username": req.session.username, "admin": req.session.admin });
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
        req.session.admin = false;
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
                req.session.admin = false;
                res.redirect("/");
            }
        });
    }
});

/** Admin form */
app.get("/admin", function (req, res) {
    // Show form, default value = current username
    res.render("admin", { "username": req.session.username, "error": null });
});
app.post("/admin", function (req, res) {
    var options = { "username": req.body.username, "error": null };
    if (!req.body.username) {
        options.error = "User name is required";
        res.render("admin", options);
    } else if (!req.body.password) {
        options.error = "Password is required";
        res.render("admin", options);
    } else if (req.body.password != password) {
        options.error = "Password is not valid";
        res.render("admin", options);
    } else if (req.body.username == req.session.username) {
        // User has not changed username, accept it as-is
        req.session.admin = true;
        res.redirect("/");
    } else if (!req.body.username.match(/^[a-zA-Z0-9\-_]{3,}$/)) {
        options.error = "User name must have at least 3 alphanumeric characters";
        res.render("admin", options);
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
                res.render("admin", options);
            } else {
                req.session.username = req.body.username;
                req.session.admin = true;
                res.redirect("/");
            }
        });
    }
});

/** WebSocket */
var sockets = require('socket.io').listen(app).of('/quiz');
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
        if (!err && session && session.username && 'boolean' == typeof session.admin) {
            // On stocke ce username dans les données de l'authentification, pour réutilisation directe plus tard
            handshakeData.username = session.username;
            handshakeData.admin = session.admin;
            // OK, on accepte la connexion
            callback(null, true);
        } else {
            // Session incomplète, ou non trouvée
            callback(err || 'User not authenticated', false);
        }
    });
  }
});

// Active sockets by session
var connections = {};
sockets.on('connection', function (socket) { // New client
    var sessionID = socket.handshake.sessionID; // Store session ID from handshake
    // this is required if we want to access this data when user leaves, as handshake is
    // not available in "disconnect" event.
    var username = socket.handshake.username; // Same here, to allow event "bye" with username
    var admin = socket.handshake.admin; // Same here, to identify the user

    var userID;

    // Create a Redis client and subscribe
    var redisClient;
    redisClient = redis.createClient();
    redisClient.on("error", function (err) {
        console.log("Error " + err);
    });

    if ('undefined' == typeof connections[sessionID]) {
        connections[sessionID] = { "length": 0 };
        // First connection
        redisClient.scard("users", function (err, id) {
            userID = id;
            redisClient.hmset("user:"+userID, "username", username, "points", 0, "pushed", false);
            redisClient.sadd("users", "user:"+userID);
        });
        sockets.emit('log', username+' joined the room', Date.now());
    }
    // Add connection to pool
    connections[sessionID][socket.id] = socket;
    connections[sessionID].length ++;

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
            sockets.emit('log', username+' left the room', Date.now());
        }
    });

    function displayScores() {
        redisClient.smembers("users", function (err, users) {
            users.forEach(function(user) {
                redisClient.hgetall(user, function (err, info) {
                    if (info['points'] > 1) {
                        sockets.emit('log', info['username']+' has '+info['points']+' points', Date.now());
                    } else {
                        sockets.emit('log', info['username']+' has '+info['points']+' point', Date.now());
                    }
                });
            });
        });
    }

    function nextQuestion() {
        sockets.emit('log', "too late! the correct answer was '"+answer+"'", Date.now());
        askQuestion();
    }

    function endGame() {
        clearTimeout(timeoutID);
        started = false;
        displayScores();
    }

    function askQuestion() {
        clearTimeout(timeoutID);
        redisClient.spop("entry.ids", function (err, id) {
            if (null != id) {
                redisClient.smembers("users", function (err, users) {
                    users.forEach(function(user) {
                        redisClient.hset(user, "pushed", false);
                    });
                });
                sockets.emit('release');
                redisClient.hgetall("entry:"+id, function (err, entry) {
                    console.log(entry);
                    question = entry["question"];
                    answer = entry["answer"];
                    sockets.emit('log', question, Date.now());
                });
                timeoutID = setTimeout(nextQuestion, maxTime);
            } else {
                sockets.emit('log', 'no more question in the database, game ended', Date.now());
                endGame();
            }
        });
    }

    // New message from client = "write" event
    socket.on('write', function (message) {
        if (message[0] != '/') {
            sockets.emit('message', username, message, Date.now());
            if (started == true && paused == false) {
                var tokens = answer.split(' ou ');
                for (var i=0; i<tokens.length; i++) {
                    if (tidyAccents(tokens[i].toLowerCase()) == tidyAccents(message.toLowerCase())) {
                        sockets.emit('log', 'correct answer', Date.now());
                        redisClient.hincrby("user:"+userID, "points", 1);
                        askQuestion();
                        return;
                    }
                }
                sockets.emit('log', 'wrong answer', Date.now());
                //redisClient.hget("user:"+userID, "points", function (err, points) {
                //    if (points > 0) {
                //        redisClient.hincrby("user:"+userID, "points", -1);
                //    }
                //});
                redisClient.hset("user:"+userID, "pushed", true);
            }
        } else {
            // User command
            commands = message.substr(1).split(" ")
            switch (commands[0]) {
                case 'help':
                    var message = "";
                    if (admin == true) {
                        message = 'start &nbsp;pause &nbsp;resume stop<br />'+
                                  'skip&nbsp;&nbsp;&nbsp;clear &nbsp;read &nbsp;&nbsp;kick<br />';
                    }
                    message += 'score &nbsp;scores flip &nbsp;&nbsp;sup<br />'+
                               'help';
                    socket.emit('log', message, Date.now());
                    break;
                case 'flip':
                    sockets.emit('message', username, '（╯°□°）╯︵ ┻━┻', Date.now());
                    break;
                case 'sup':
                    sockets.emit('message', username, '¯\\_(ツ)_/¯', Date.now());
                    break;
                case 'pause':
                    if (admin == true) {
                        if (started == true) {
                            if (paused == false) {
                                sockets.emit('log', username+' paused the game', Date.now());
                                clearTimeout(timeoutID);
                                paused = true;
                            }
                        } else {
                            socket.emit('log', 'no game started', Date.now());
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'resume':
                    if (admin == true) {
                        if (started == true) {
                            if (paused == true) {
                                sockets.emit('log', username+' resumed the game', Date.now());
                                timeoutID = setTimeout(nextQuestion, maxTime);
                                paused = false;
                            }
                        } else {
                            socket.emit('log', 'no game started', Date.now());
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'start':
                    if (admin == true) {
                        if (started == true) {
                            socket.emit('log', 'a game has already been started, stop it first', Date.now());
                        } else {
                            redisClient.scard("entry.ids", function (err, numEntries) {
                                if (numEntries > 0) {
                                    sockets.emit('log', username+' started a new game', Date.now());
                                    redisClient.smembers("users", function (err, users) {
                                        users.forEach(function(user) {
                                            redisClient.hset(user, "points", 0);
                                        });
                                    });
                                    askQuestion();
                                    started = true;
                                } else {
                                    socket.emit('log', 'no question in the database, use /read', Date.now());
                                }
                            });
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'stop':
                    if (admin == true) {
                        if (started == true) {
                            sockets.emit('log', username+' ended the game', Date.now());
                            endGame();
                        } else {
                            socket.emit('log', 'no game started', Date.now());
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'skip':
                    if (admin == true) {
                        if (started == true) {
                            if (paused == false) {
                                sockets.emit('log', username+' skipped this question', Date.now());
                                sockets.emit('log', "the correct answer was '"+answer+"'", Date.now());
                                askQuestion();
                            }
                        } else {
                            socket.emit('log', 'no game started', Date.now());
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'clear':
                    if (admin == true) {
                        redisClient.smembers("entry.ids", function (err, ids) {
                            for (var i=0; i<ids.length; i++) {
                                redisClient.srem("entry.ids", ids[i]);
                            }
                        });
                        sockets.emit('log', username+' emptied the database', Date.now());
                    } else {
                        socket.emit('log', 'no game started', Date.now());
                    }
                    break;
                case 'read':
                    if (admin == true) {
                        if (commands[1]) {
                            // Read questions in file
                            var i = 0;
                            stream = fs.createReadStream(commands[1]);
                            new lazy(stream)
                            .lines
                            .forEach(function(line) {
                                i++;
                                id = Math.round(i/2)-1;
                                if (i%2 == 0) {
                                    redisClient.sadd("entry.ids", id);
                                    redisClient.hset("entry:"+id, "answer", line.toString());
                                } else {
                                    redisClient.hset("entry:"+id, "question", line.toString());
                                }
                            });
                            stream.on('end', function(close) {
                                sockets.emit('log', username+' added '+Math.round(i/2)+' questions in the database', Date.now());
                            });
                        } else {
                            socket.emit('log', 'missing operand', Date.now());
                        }
                    } else {
                        socket.emit('log', 'no game started', Date.now());
                    }
                    break;
                    /*
                case 'names':
                    redisClient.smembers("users", function (err, users) {
                        var usernames = "";
                        users.forEach(function(user) {
                            redisClient.hget(user, "username", function (err, name) {
                                usernames += ' '+name;
                            });
                        });
                        socket.emit('log', usernames, Date.now());
                    });
                    break;
                    */
                case 'kick':
                    if (admin == true) {
                        if (commands[1]) {
                            redisClient.smembers("users", function (err, users) {
                                users.forEach(function(user) {
                                    redisClient.hget(user, "username", function (err, name) {
                                        if (commands[1] == name)
                                        {
                                            redisClient.srem("users", user, function (err, val) {
                                                console.log(val);
                                                socket.emit('log', username+' kicked '+name, Date.now());
                                            });
                                        }
                                    });
                                });
                            });
                        } else {
                            socket.emit('log', 'missing operand', Date.now());
                        }
                    } else {
                        socket.emit('log', 'no game started', Date.now());
                    }
                    break;
                case 'score':
                    redisClient.hget("user:"+userID, "points", function (err, points) {
                        if (points > 1) {
                            socket.emit('log', username+' has '+points+' points', Date.now());
                        } else {
                            socket.emit('log', username+' has '+points+' point', Date.now());
                        }
                    });
                    break;
                case 'scores':
                    displayScores();
                    break;
                default:
                    socket.emit('log', 'unknown command', Date.now());
            }
        }
    });

    // New action from client = "push" event
    socket.on('push', function () {
        //sockets.emit('log', username+'?', Date.now());
    });

    if (started == true) {
        socket.emit('log', 'a game has already been started', Date.now());
        socket.emit('log', question, Date.now());
    }
});

/** Start server */
if (!module.parent) {
    app.listen(port)
}
 
