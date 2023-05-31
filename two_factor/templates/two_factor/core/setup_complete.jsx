import React from 'react';
import { Link } from 'react-router-dom';

const EnableTwoFactorAuth = ({ phoneMethods }) => {
  return (
    <div>
      <h1>Enable Two-Factor Authentication</h1>

      <p>Congratulations, you've successfully enabled two-factor authentication.</p>

      {!phoneMethods ? (
        <p>
          <Link to="/profile" className="btn btn-block btn-secondary">
            Back to Account Security
          </Link>
        </p>
      ) : (
        <div>
          <p>
            However, it might happen that you don't have access to your primary token device.
            To enable account recovery, add a phone number.
          </p>

          <Link to="/profile" className="float-right btn btn-link">
            Back to Account Security
          </Link>
          <p>
            <Link to="/phone-create" className="btn btn-success">
              Add Phone Number
            </Link>
          </p>
        </div>
      )}
    </div>
  );
};

export default EnableTwoFactorAuth;
