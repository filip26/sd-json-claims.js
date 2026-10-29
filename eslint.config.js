
import jsdoc from 'eslint-plugin-jsdoc';

export default [
  {
    files: ['**/*.js'],
    plugins: {
      jsdoc,
    },
    rules: {
      'jsdoc/check-indentation': 'error',
      'jsdoc/check-line-alignment': 'error',
    },
  },
];

