# burp-template

## Author

Written by Anthony Marquez ([@BoogeyMarquez](https://twitter.com/boogeymarquez))

## Description


## Building Instructions

Make sure you have `ant` installed

```bash
brew install ant
```

Navigate to base of directory, should see `build.xml` file.

```bash
ant dist
```

You should have a `burp-template-YYYYMMDD.jar` file in the `dist/` folder.  Load it within Burp and you are good to go.

## Loading Instructions
Launch BurpSuite, go to the Extender tab and then open the Extensions tab and click on "Add". In the dialog window,
select "java" as Extension Type and select the burp-template.jar. For further details about BurpSuite extensions, refer
to their [documentation](https://portswigger.net/burp/help/extender.html#loading).
