import mimetypes
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import magic
import tika  # type: ignore[import-untyped]
from karton.core import Config, Karton, RemoteResource, Task
from karton.core.backend import KartonBackend
from lxml import etree
from magika import Magika  # type: ignore[import-untyped]
from tika import parser

MAGIKA_RELIABILITY_THRESHOLD = 0.8


class FiletypeEngine(Karton):
    identity = 'karton.filetype'
    version = '1.0.0'
    filters = [  # noqa: RUF012
        {'type': 'sample', 'kind': 'raw'},
    ]
    magik: Magika
    shared_mime_info: etree._ElementTree | Any

    def populate_mimetypes_types(self) -> None:  # noqa: PLR0915
        # These mime types are from magika and they're not in the basic knowledge of the current system
        # https://github.com/google/magika/blob/main/rust/lib/src/content.rs
        mimetypes.add_type('application/x-dosexec', '.pe')
        mimetypes.add_type('application/chm', '.chm')
        mimetypes.add_type('application/msonenote', '.one')
        mimetypes.add_type('application/sgml', '.sgml')
        mimetypes.add_type('application/sla', '.sla')
        mimetypes.add_type('application/typescript', '.ts')
        mimetypes.add_type('application/vnd.ms-outlook', '.msg')
        mimetypes.add_type('application/x-ace-compressed', '.ace')
        mimetypes.add_type('application/x-android-dex', '.dex')
        mimetypes.add_type('application/x-android-dey', '.dey')
        mimetypes.add_type('application/x-bplist', '.bplist')
        mimetypes.add_type('application/x-bytecode.python', '.pyc')
        mimetypes.add_type('application/x-chrome-extension', '.crx')
        mimetypes.add_type('application/x-coff', '.coff')
        mimetypes.add_type('application/x-executable-elf', '.elf')
        mimetypes.add_type('application/x-hfs', '.hfs')
        mimetypes.add_type('application/x-java-applet', '.jar')
        mimetypes.add_type('application/x-mach-o', '.macho')
        mimetypes.add_type('application/x-ms-compress-szdd', '.szzd')
        mimetypes.add_type('application/x-ms-ese', '.ese')
        mimetypes.add_type('application/x-msdownload', '.pe')
        mimetypes.add_type('application/x-mspublisher', '.pub')
        mimetypes.add_type('application/x-pem-file', '.pem')
        mimetypes.add_type('application/x-plist', '.plist')
        mimetypes.add_type('application/x-rar', '.rar')
        mimetypes.add_type('application/x-rust', '.rs')
        mimetypes.add_type('application/x-scala', '.sc')
        mimetypes.add_type('application/x-smali', '.smali')
        mimetypes.add_type('application/x-sql', '.sql')
        mimetypes.add_type('application/x-udf-image', '.udf')
        mimetypes.add_type('application/x-vhd', '.vhd')
        mimetypes.add_type('application/x-windows-driver', '.sys')
        mimetypes.add_type('application/x-yaml', '.yml')
        mimetypes.add_type('font/sfnt', '.ttf')
        mimetypes.add_type('image/jpeg2000', '.jpg')
        mimetypes.add_type('image/x-dwg', '.dwg')
        mimetypes.add_type('inode/x-empty', '.')
        mimetypes.add_type('text/coffeescript', '.coffee')
        mimetypes.add_type('text/rtf', '.rtf')
        mimetypes.add_type('text/tsv', '.tsv')
        mimetypes.add_type('text/vbscript', '.vbs')
        mimetypes.add_type('text/x-R', '.R')
        mimetypes.add_type('text/x-c', '.c')
        mimetypes.add_type('text/x-clojure', '.clj')
        mimetypes.add_type('text/x-dockerfile', '.dockerfile')
        mimetypes.add_type('text/x-golang', '.go')
        mimetypes.add_type('text/x-julia', '.jl')
        mimetypes.add_type('text/x-lisp', '.lisp')
        mimetypes.add_type('text/x-msdos-batch', '.bat')
        mimetypes.add_type('text/x-php', '.php')
        mimetypes.add_type('text/x-prolog', '.pl')
        mimetypes.add_type('text/x-shellscript', '.sh')
        mimetypes.add_type('text/x-swift', '.swift')
        mimetypes.add_type('text/x-vbscript', '.vbs')
        mimetypes.add_type('text/ocaml', '.ml')
        mimetypes.add_type('text/zig', '.zig')

    def __init__(
        self,
        config: Config | None = None,
        identity: str | None = None,
        backend: KartonBackend | None = None,
    ) -> None:
        super().__init__(config=config, identity=identity, backend=backend)
        self.populate_mimetypes_types()
        self.magik = Magika()
        tika.initVM()
        self.shared_mime_info = etree.parse('freedesktop.org.xml.in')  # nosec: B320  # noqa: S320

    #
    # Functions to operate on the mimetype itself
    #

    def shared_mime_get_extension(self, mime: str) -> str | None:
        if not self.shared_mime_info:
            return None
        namespaces = {'ns': 'http://www.freedesktop.org/standards/shared-mime-info'}
        mime_type_node = self.shared_mime_info.xpath(
            f'//ns:mime-type[@type="{mime}"]',
            namespaces=namespaces,
        )

        if isinstance(mime_type_node, list) and isinstance(mime_type_node[0], etree._Element):  # noqa: SLF001
            glob_node = mime_type_node[0].xpath('ns:glob', namespaces=namespaces)
            if isinstance(glob_node, list) and isinstance(glob_node[0], etree._Element):  # noqa: SLF001
                pattern = glob_node[0].get('pattern')
                if pattern:
                    return pattern[2:]

        return None

    def mime_get_toplevel(self, mime: str) -> str | None:
        parts = mime.split('/')
        if len(parts) == 1:
            return None
        return parts[0]

    def mime_get_extension(self, mime: str) -> str | None:
        if not mime:
            return None
        ext = mimetypes.guess_extension(mime, strict=False)
        if ext:
            return ext[1:]
        return self.shared_mime_get_extension(mime)

    def mime_trim_minimal(self, mime: str) -> str:
        return mime.split()[0].replace(';', '')

    #
    # TRID
    #

    def run_trid(self, path: str) -> tuple[str | None, str | None]:
        try:
            result = subprocess.run(
                ['trid', path],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                analysis_block = result.stdout[result.stdout.find('Analyzing...') :]
                extension = analysis_block[analysis_block.find('(') + 1 : analysis_block.find(')')].lower().replace('.', '')
                mime, _ = mimetypes.guess_type(f'x.{extension}', strict=False)
                return extension, mime
        except Exception as _:
            pass
        return None, None

    #
    # Internal helping utils
    #

    def is_archive_mime(self, mime: str) -> bool:
        archive_mimes = [
            'application/gzip',
            'application/vnd.ms-cab-compressed',
            'application/x-7z-compressed',
            'application/x-ace-compressed',
            'application/x-arc',
            'application/x-archive',
            'application/x-arj',
            'application/x-brotli',
            'application/x-bzip-compressed-tar',
            'application/x-bzip2',
            'application/x-cabinet',
            'application/x-compress',
            'application/x-cpio',
            'application/x-dar',
            'application/x-debian-package',
            'application/x-freearc',
            'application/x-gtar',
            'application/x-hqx',
            'application/x-iso9660-image',
            'application/x-jar',
            'application/x-java-archive',
            'application/x-lha',
            'application/x-lz4',
            'application/x-lzh-compressed',
            'application/x-lzh',
            'application/x-lzip-compressed-tar',
            'application/x-lzip',
            'application/x-lzma',
            'application/x-par2',
            'application/x-rar-compressed',
            'application/x-rpm',
            'application/x-sbx',
            'application/x-shar',
            'application/x-tar',
            'application/x-tzo',
            'application/x-wim',
            'application/x-xar',
            'application/x-xz-compressed-tar',
            'application/x-xz',
            'application/x-z',
            'application/x-zip-compressed',
            'application/zip',
        ]

        return mime in archive_mimes

    def generate_classifiable(
        self,
        mime: str,
        category_suggestion: str | None = None,
        extension_suggestion: str | None = None,
        extra: dict | None = None,
    ) -> dict[str, Any]:
        mime = self.mime_trim_minimal(mime)
        category = category_suggestion if category_suggestion else self.mime_get_toplevel(mime)
        mime_extension = self.mime_get_extension(mime)
        extension = mime_extension if mime_extension else extension_suggestion

        if self.is_archive_mime(mime):
            category = 'archive'

        # Consolidate matches
        # There are other extensions too, but they're extremely unlikely to find and maybe we even want to keep their extensions
        if extension_suggestion in ('exe', 'dll', 'pebin', 'drv'):
            extension_suggestion = 'pe'

        classified = {
            'kind': category,
            'extension': extension,
            'mime': mime,
        }
        if extra:
            classified.update(extra)

        return classified

    #
    # IDK
    #

    def identify_path(self, path: str) -> dict[str, Any]:
        # We need both to rule out some potential FPs
        magika_match = self.magik.identify_path(Path(path))
        magika_mime = magika_match.output.mime_type

        tika_match = parser.from_file(path, service='meta')
        tika_mime = ''
        if isinstance(tika_match, dict) and 'metadata' in tika_match and isinstance(tika_match['metadata'], dict) and 'Content-Type' in tika_match['metadata']:
            tika_mime = tika_match['metadata']['Content-Type']

        # If Tika finds textual type, but magika finds something else
        # Eg. sometimes obfuscated files may be 'audio' types
        if self.mime_get_toplevel(tika_mime) == 'text' and self.mime_get_toplevel(magika_mime) != 'text':
            # It's text based, right now we have don't have a reliable way to detect further
            return self.generate_classifiable(tika_mime)

        # We found a reliable magika match, let's use that!
        if magika_match.output.mime_type != 'application/octet-stream' and magika_match.output.score > MAGIKA_RELIABILITY_THRESHOLD:
            extra = None
            extension_suggestion = magika_match.output.ct_label
            group_suggestion = None
            # Check for PE format, we'll add extra params to find the actual extension
            if magika_mime == 'application/x-dosexec':
                magic_string = magic.from_file(path, mime=False)
                extra = {
                    'petype': magic_string[magic_string.find('(') + 1 : magic_string.find(')')].lower(),
                }
            if magika_match.output.group == 'archive':
                group_suggestion = magika_match.output.group
            return self.generate_classifiable(
                magika_mime,
                group_suggestion,
                extension_suggestion,
                extra,
            )

        # Next try is FILE Magic:
        # Note that we get MIME, but EXT is generated!
        magic_mime = magic.from_file(path, mime=True)
        magic_extension = self.mime_get_extension(magic_mime)
        if magic_mime and magic_extension:
            return self.generate_classifiable(magic_mime)

        # Next step, TRID:
        # Note that we get EXT, but MIME is generated
        trid_extension, trid_mime = self.run_trid(path)
        if trid_mime and trid_extension:
            return self.generate_classifiable(trid_mime)

        # Since FILE and TRID had both generated elements, let's try if their combination
        # can result in a good match:
        if magic_mime and trid_extension:
            return self.generate_classifiable(magic_mime, None, trid_extension)

        # Let's see if ANY of the previous mimetypes had value, maybe
        # the logic just dismissed it for whatever reason
        default_mime = next(
            (mime for mime in [magika_mime, tika_mime, magic_mime, trid_mime] if mime is not None),
            'application/octet-stream',
        )
        default_extension = trid_extension if trid_extension else 'bin'

        # Worst case it's 'application/octet-stream' with '.bin' extension
        return self.generate_classifiable(default_mime, None, default_extension)

    def process(self, task: Task) -> None:
        sample = task.get_resource('sample')
        if not isinstance(sample, RemoteResource):
            return

        derived_header = {
            'type': 'sample',
            'stage': 'recognized',
            'extension': '',  # To be filled by `identify_path`
            'mime': '',  # To be filled by `identify_path`
            'kind': '',  # To be filled by `identify_path`
            'quality': task.headers.get('quality', 'high'),
        }

        # Download the file and update the previous header
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            sample.download_to_file(tmp.name)
            derived_header.update(self.identify_path(tmp.name))
        finally:
            Path(tmp.name).unlink()

        derived_task = task.derive_task(derived_header)

        # Populate the tags
        tags = ['type:' + derived_header['kind'] + ':' + derived_header['extension']]
        if derived_task.has_payload('tags'):
            tags += derived_task.get_payload('tags')
            derived_task.remove_payload('tags')

        derived_task.add_payload('tags', tags)

        # We're done!
        self.send_task(derived_task)


if __name__ == '__main__':
    FiletypeEngine().loop()
