// Load modules

var Hoek = require('hoek');
var Boom = require('boom');
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

    urls: {
        app: '/oz/app',
        reissue: '/oz/reissue',
        rsvp: '/oz/rsvp'
    }
};


exports.register = function (plugin, options, next) {

    plugin.auth.scheme('oz', internals.oz);
    next();
};


internals.oz = function (server, options) {

    Hoek.assert(options, 'Invalid hawk scheme options');
    Hoek.assert(options.oz, 'Missing required oz configuration');

    var settings = Hoek.applyToDefaults(internals.defaults, options);

    // Add protocol endpoints

    var endpoint = function (name) {

        var endpoint = {
            auth: false,                            // Override any defaults
            handler: function (request, reply) {

                Oz.endpoints[name](request.raw.req, request.payload, settings.oz, function (err, response) {

                    return reply(err || response);
                });
            }
        };

        return endpoint;
    };

    server.route([
        { method: 'POST', path: settings.urls.app, config: endpoint('app') },
        { method: 'POST', path: settings.urls.reissue, config: endpoint('reissue') },
        { method: 'POST', path: settings.urls.rsvp, config: endpoint('rsvp') }
    ]);

    var scheme = {
        authenticate: function (request, reply) {

            Oz.server.authenticate(request.raw.req, settings.oz.encryptionPassword, {}, function (err, credentials, artifacts) {

                return reply(err, { credentials: credentials, artifacts: artifacts });
            });
        }
    };

    return scheme;
};
