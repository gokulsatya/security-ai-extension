const path = require('path');

module.exports = {
  entry: {
    background: './src/extension/background.js',
    popup: './src/extension/popup.js'
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist')
  },
  mode: 'development'
};