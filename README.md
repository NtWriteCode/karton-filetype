# Karton Filetype Engine

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://forthebadge.com)
[![forthebadge](http://forthebadge.com/images/badges/built-with-love.svg)](https://forthebadge.com)

## A Different Approach to File Classification for MWDB Karton

The Karton Filetype Engine is a powerful tool designed for the MWDB Karton system. It's inspired by the [karton-classifier](https://github.com/CERT-Polska/karton-classifier), however it follows an entirely different approach. While the classifier tries to put all the possible labels on it hoping that at least one of the will be correct and consumed by the correct consumer, this repository tries its best to assign it to a SINGLE, but as correct file type as possible.

## Utilized third party tools

In order to achieve the best accuracy Filetype engine uses all of the following tools:

- [Magika](https://github.com/google/magika)
- [Apache Tika](https://tika.apache.org/)
- [File magic](https://linux.die.net/man/5/magic)
- [TrID](https://mark0.net/soft-trid-e.html)

Also it utizises some external database/lists too to improve its mimetype knowledge:

- [Python 'mimetypes'](https://docs.python.org/3/library/mimetypes.html)
- [Freedesktop: shared-mime-info](https://wiki.freedesktop.org/www/Software/shared-mime-info/)

## Input/Output

### Consumes

    {
        "type": "sample",
        "kind": "raw"
        "payload": {
            "magic":  "output from 'file' command",
            "sample": <Resource>
        }
    }

### Produces

It produces a similar structure to classifier, however in no way it's compatible with that.

    {
    'type': 'sample',
    'stage': 'recognized',
    'extension': '',    # Literally an extension used by the file format
                        # In some cases it's not the actual extension, but a placeholder, for example
                        # for PEs it's "pe", which is nonexistent
                        # By default "bin" is used.
    'mime': '',         # The actual MIME type it identifies. Most of the cases it's provided by Magika and Tika,
                        # hence they should be stable to use.
                        # In case of no match "application/octet-stream" is used as default
    'kind': '',         # A mixed hybrid of the TOP level items from:
                        # https://www.digipres.org/formats/mime-types/
                        # And one extra-custom introduced element for archives.
                        # So, every mimetype will have either the TOP mimetype element or "archive"
    ... (other fields are derived from incoming task)
    }

I know, `Filetype`is more complicated to check. TODO

## Getting Started

TODO
