// Load modules

var Hoek = require('hoek');
var Oz = require('oz');


// Declare internals

var internals = {};


// Defaults

internals.defaults = {

    // Oz options

    oz: {
        encryptionPassword: null,
        loadAppFunc: null,
        loadGrantFunc: null,
        hawk: null,
        ticket: null
    },

    // Scarecrow options

    defaultMode: null,

    urls: {
        app: '/oz/app',
        reissue: '/oz/reissue',
        rsvp: '/oz/rsvp'
    }
};


exports.register = function (plugin, options, next) {

    // Validate options and apply defaults

    var settings = Hoek.applyToDefaults(internals.defaults, options);

    // Add protocol endpoints

    var endpoint = function (name) {

        var endpoint = {
            auth: false,                            // Override any defaults
            handler: function (request) {

                Oz.endpoints[name](request.raw.req, request.payload, settings.oz, function (err, response) {

                    return request.reply(err || response);
                });
            }
        };

        return endpoint;
    };

    plugin.route([
        { method: 'POST', path: settings.urls.app, config: endpoint('app') },
        { method: 'POST', path: settings.urls.reissue, config: endpoint('reissue') },
        { method: 'POST', path: settings.urls.rsvp, config: endpoint('rsvp') }
    ]);

    // Register scheme

    plugin.auth('oz', {
        implementation: {
            authenticate: function (request, callback) {

                Oz.server.authenticate(request.raw.req, settings.oz.encryptionPassword, {}, function (err, credentials, artifacts) {

                    return callback(err, credentials, { artifacts: artifacts });
                });
            }
        },
        defaultMode: settings.defaultMode
    });

    next();
};


