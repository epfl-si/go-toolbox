# Go Toolbox
## Summary
This a Go module to centralize all common functions and utilities we use in our Go development at IAM team.

## Release
To create a new release :

Retrieve highest version:
```git tag -l --sort=version:refname | tail -1```

```git tag v0.x.y```

```git push --tags```

## Packages
### api
API related functions to call API gateway endpoints. Provides a generic function CallApi and specialized functions for specific items (GetPerson, GetAuthorizations, GetAccreds, etc.).
It also provides the structures for the most common business artefacts with JSON annotation for unmarshalling.

### log
It provides mainly a GetLogger function to get a commonly configured zap logger.

### database
It provides a function to get a gorm.DB database handler.

### test
Provides common functions for testings, like MakeRequest to make a request to a local backend and CompareResponses to compare an API response content to a reference file in assets/tests folder.
