/**
 * Security Utility: Immutable Property Helper
 * Creates non-writable, non-configurable properties to prevent tampering
 */

/**
 * Make a single property immutable on an object
 * @param {Object} obj - The target object
 * @param {string} propertyName - Name of the property
 * @param {*} value - Value to set
 */
function makeImmutable(obj, propertyName, value) {
  Object.defineProperty(obj, propertyName, {
    value: value,
    writable: false,
    enumerable: true,
    configurable: false
  });
}

/**
 * Make multiple properties immutable at once
 * @param {Object} obj - The target object
 * @param {Object} properties - Key-value pairs of properties to make immutable
 * 
 * @example
 * makeImmutableProperties(this, {
 *   enabled: true,
 *   config: configObject,
 *   silent: false
 * });
 */
function makeImmutableProperties(obj, properties) {
  for (const [key, value] of Object.entries(properties)) {
    makeImmutable(obj, key, value);
  }
}

module.exports = {
  makeImmutable,
  makeImmutableProperties
};
