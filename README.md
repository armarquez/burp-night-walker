# burp-night-walker

## Author

Written by Anthony Marquez ([@BoogeyMarquez](https://twitter.com/boogeymarquez))

## Description

Burp extender plugin to set a time when all requests should begin being redirected to another url. Currently this is the best way to "drop" requests for many of Burps tools. This extension was made while performing a late night assessment when I didn't want to continue an Intruder attack after a certain time.

## Building Instructions

Make sure you have `ant` installed

```bash
brew install ant
```

Navigate to base of directory, should see `build.xml` file.

```bash
ant dist
```

You should have a `burp-night-walker-YYYYMMDD.jar` file in the `dist/` folder.  Load it within Burp and you are good to go.

## Loading Instructions
Launch BurpSuite, go to the Extender tab and then open the Extensions tab and click on "Add". In the dialog window,
select "java" as Extension Type and select the burp-night-walker.jar. For further details about BurpSuite extensions, refer
to their [documentation](https://portswigger.net/burp/help/extender.html#loading).
