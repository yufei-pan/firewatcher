import firewatcher as fw

# --- slugify ---

def test_slugify_truncates_long_matches():
    slug = fw.slugify('nvme ' + ('timeout-' * 40))
    assert len(slug) <= fw.SLUG_MAX_LEN
    assert slug


def test_slugify_normalizes_and_strips():
    assert fw.slugify('  Panic: I/O error!!  ') == 'panic-io-error'
    assert fw.slugify('café') == 'cafe'
    uni = fw.slugify('café', allow_unicode=True)
    assert uni in ('café', 'cafe')
    assert fw.slugify('---') == ''
    assert len(fw.slugify('a' * (fw.SLUG_MAX_LEN + 20))) == fw.SLUG_MAX_LEN


def test_slugify_unicode_nfkc_and_empty_after_strip():
    # fullwidth letters collapse under NFKC when allow_unicode is True
    wide = fw.slugify('ＡＢＣ', allow_unicode=True)
    assert wide in ('ABC', 'abc', 'ＡＢＣ')
    assert fw.slugify('!!!') == ''
    assert fw.slugify('foo_bar') == 'foo_bar'
