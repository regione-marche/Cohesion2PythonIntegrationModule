# CohesionIntegration - Python package

A simple and straightforward Cohesion integration package

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install CohesionIntegration.

```bash
pip install CohesionIntegration
```

## Usage

Test FastAPI application at [Cohesion2PythonIntegrationTest](https://github.com/regione-marche/Cohesion2PythonIntegrationTest)
Download the code and properly setup the config.json file 


```json
{
    "sso.check.url": "https://cohesion2.regione.marche.it/SPManager/WAYF.aspx",
    "sso.webCheckSessionSSO": "https://cohesion2.regione.marche.it/SPManager/webCheckSessionSSO.aspx",
    "sso.additionalData": "http://127.0.0.1:8000/logout",
    "site.URLLogin": "http://127.0.0.1:8000/callback",
    "site.URLLogout": "http://127.0.0.1:8000/logout",
    "site.IndexURL": "http://127.0.0.1:8000/",
    "site.ID_SITO": "TEST",
    "debug": true
}
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)