process.env.LOG_LEVEL = 'none';

module.exports = {
  roots: ['<rootDir>'],
  transform: {
    '^.+\\.ts?$': [
      'ts-jest',
      {
        isolatedModules: true,
        tsconfig: {
          module: 'commonjs',
        },
        diagnostics: {
          warnOnly: false,
        },
      },
    ],
  },
  testRegex: '(__tests__/.*|(\\.|/)(test|spec))\\.ts?$',
  moduleFileExtensions: ['ts', 'js', 'json', 'node'],
};
