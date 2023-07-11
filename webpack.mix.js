const mix = require('laravel-mix');

/*
 |--------------------------------------------------------------------------
 | Mix Asset Management
 |--------------------------------------------------------------------------
 |
 | Mix provides a clean, fluent API for defining some Webpack build steps
 | for your Laravel applications. By default, we are compiling the CSS
 | file for the application as well as bundling up all the JS files.
 |
 */

mix.options({
    postCss: [
        require('autoprefixer'),
    ],
});

mix.browserSync('127.0.0.1:8000');

mix.setPublicPath('public');

mix.webpackConfig({
    resolve: {
        extensions: ['.js', '.vue'],
        alias: {
            '@': __dirname + 'resources'
        }
    },
    output: {
        chunkFilename: 'js/chunks/[name].js',
    },
}).react();

// used to run app using reactjs
mix.js('resources/larasoft/src/main.js', 'public/js/app.js').version();
mix.copy('resources/larasoft/public', 'public/frontend');
