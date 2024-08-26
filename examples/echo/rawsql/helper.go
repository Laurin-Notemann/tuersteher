package rawsql

import "database/sql"

func CreateUserWithCreds(dbCon *sql.DB, name, email, salt string, passwordHash []byte) (PGUser, error) {
	user, err := InsertUser(
		dbCon,
		&PGUser{
			Name:  name,
			Email: email,
		})
	if err != nil {
		return PGUser{}, err
	}

	if err = InsertUserCredentials(
		dbCon,
		&PGUserCredentials{
			UserId:       user.Id,
			PasswordHash: passwordHash,
			Salt:         salt,
		},
	); err != nil {
		return PGUser{}, err
	}

	return user, nil
}

func FindUserAndCredsByEmail(dbCon *sql.DB, email string) (PGUser, PGUserCredentials, error) {
	user, err := SelectOneUserByEmail(dbCon, email)
	if err != nil {
		return PGUser{}, PGUserCredentials{}, err
	}

	userCreds, err := SelectUserCredentialsByUserId(dbCon, user.Id)
	if err != nil {
		return PGUser{}, PGUserCredentials{}, err
	}

	return user, userCreds, nil
}

func CreateUserWithGoogleOAuth(dbCon *sql.DB, name, email, providerUserId string) (PGUser, error) {
	user, err := InsertUser(
		dbCon,
		&PGUser{
			Name:  name,
			Email: email,
		})
	if err != nil {
		return PGUser{}, err
	}

	if err = InsertOAuthUserAccount(
		dbCon,
		&PGOAuthUserAccount{
			UserId:         user.Id,
			ProviderId:     "google",
			ProviderUserId: providerUserId,
		},
	); err != nil {
		return PGUser{}, err
	}

	return user, nil
}
