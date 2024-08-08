import argparse
import collections
import configparser
from datetime import datetime
import grp, pwd
from fnmatch import fnmatch
import hashlib
from math import ceil
import os
import re
import sys
import zlib

argparser = argparse.ArgumentParser(description="My custom content tracker")
argsubparsers = argparser.add_subparsers(title="Commands", dest="command")
argsubparsers.required = True
argsp = argsubparsers.add_parser("init", help="Initialize a new empty repository.")
argsp.add_argument("path",
                    metavar="directory",
                    nargs="?",
                    default=".",
                    help="Where to create the repository")
argsp = argsubparsers.add_parser("cat-file", help="Provide content of repository content.")
argsp.add_argument("type",
                   metavar="type",
                   choices=["blob", "commit", "tag", "tree"],
                   help="Specify the type")
argsp.add_argument("object",
                   metavar="object",
                   help="The object to display")
argsp = argsubparsers.add_parser("hash-object", help="Compute object ID and optionally creates a blob from a file.")
argsp.add_argument("-t",
                   metavar="type",
                   dest="type",
                   choices=["blob", "commit", "tag", "tree"],
                   default="blob",
                   help="Specify the type")
argsp.add_argument("-w",
                   dest="write",
                   action="store_true",
                   help="Actually write the object into the database")
argsp.add_argument("path",
                   help="Read object from <file>")
argsp = argsubparsers.add_parser("log", help="Display history of a given commit.")
argsp.add_argument("commit",
                   default="HEAD",
                   nargs="?",
                   help="Commit to start from")
argsp = argsubparsers.add_parser("ls-tree", help="Pretty-print a tree object.")
argsp.add_argument("-r",
                   dest="recursive",
                   action="store_true",
                   help="Recurse into subtrees.")
argsp.add_argument("tree",
                   help="A tree-ish object.")
argsp = argsubparsers.add_parser("checkout", help="Checkout a commit inside of a directory.")
argsp.add_argument("commit",
                   help="the commit or tree to checkout.")
argsp.add_argument("path",
                   help="The EMPTY directory to checkout on.")
argsp = argsubparsers.add_parser("show-ref", help="List references.")
argsp = argsubparsers.add_parser("tag", help="List and create tags.")
argsp.add_argument("-a",
                    action="store_true",
                    dest="create_tag_object",
                    help="Whether or not we create a tag object.")
argsp.add_argument("name",
                    nargs="?",
                    help="The new tag's name.")
argsp.add_argument("object",
                   default="HEAD",
                   nargs="?",
                   help="The object the new tag will point to.")
argsp = argsubparsers.add_parser("rev-parse", help="Parse revision (or other objects) identifiers.")
argsp.add_argument("--wyag-type",
                   metavar="type",
                   dest="type",
                   choices=[ "blob", "commit", "tag", "tree" ],
                   default=None,
                   help="Specify the expected type.")
argsp.add_argument("name",
                   help="The name to parse.")
argsp = argsubparsers.add_parser("ls-files", help="List all the stage files")
argsp.add_argument("--verbose",
                   action="store_true",
                   help="Show everything. EVERYTHING!")
argsp = argsubparsers.add_parser("check-ignore", help="Check path(s) against ignore rules")
argsp.add_argument("path",
                   nargs="+",
                   help="Paths to check.")
argsp = argsubparsers.add_parser("status", help="Show the working tree status.")
argsp = argsubparsers.add_parser("rm", help="Remove files from the working tree and the index.")
argsp.add_argument("path",
                   nargs="+",
                   help="Files to remove.")
argsp = argsubparsers.add_parser("add", help="Add files contents to the index.")
argsp.add_argument("path",
                   nargs="+",
                   help="Files to add.")
argsp = argsubparsers.add_parser("commit", help="Record changes to the repository.")
argsp.add_argument("-m",
                   metavar="message",
                   dest="message",
                   help="Message to associate with this commit.")


def main(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)
    match args.command:
        case "add"          : cmd_add(args)
        case "cat-file"     : cmd_cat_file(args)
        case "check-ignore" : cmd_check_ignore(args)
        case "checkout"     : cmd_checkout(args)
        case "commit"       : cmd_commit(args)
        case "hash-object"  : cmd_hash_object(args)
        case "init"         : cmd_init(args)
        case "log"          : cmd_log(args)
        case "ls-files"     : cmd_ls_files(args)
        case "ls-tree"      : cmd_ls_tree(args)
        case "rev-parse"    : cmd_rev_parse(args)
        case "rm"           : cmd_rm(args)
        case "show-ref"     : cmd_show_ref(args)
        case "status"       : cmd_status(args)
        case "tag"          : cmd_tag(args)
        case _              : print("Bad Command.")


def cmd_init(args):
    repo_create(args.path)

def cmd_cat_file(args):
    repo = repo_find()
    cat_file(repo, args.object, fmt=args.type.encode())

def cmd_hash_object(args):
    if args.write:
        repo = repo_find()
    else:
        repo = None

    with open(args.path, "rb") as f:
        sha = object_hash(f, args.type.encode(), repo)
        print(sha)

def cmd_log(args):
    repo = repo_find()
    print("digraph wyaglog{")
    print("  node[shape=rect]")
    log_graphviz(repo, object_find(repo, args.commit), set())
    print("}")

def cmd_ls_tree(args):
    repo = repo_find()
    ls_tree(repo, args.tree, args.recursive)

def cmd_checkout(args):
    repo = repo_find()
    obj = object_read(repo, object_find(repo, args.commit))
    # Get the tree if we are starting with a commit
    if obj.fmt == b'commit':
        obj = object_read(repo, obj.kvlm[b'tree'].decode("ascii"))

    # Path must be an empty directory
    if os.path.exists(args.path):
        if not os.path.isdir(args.path):
            raise Exception("Not a directory {0}!".format(args.path))
        if os.listdir(args.path):
            raise Exception("Not empty {0}!".format(args.path))
    else:
        os.makedirs(args.path)

    # Run checkout
    tree_checkout(repo, obj, os.path.realpath(args.path))

def cmd_show_ref(args):
    repo = repo_find()
    refs = ref_list(repo)
    show_ref(repo, refs, prefix="refs")

def cmd_tag(args):
    repo = repo_find()
    if args.name:
        tag_create(repo, args.name, args.object, create_tag_object=args.create_tag_object)
    else:
        refs = ref_list(repo)
        show_ref(repo, refs["tags"], with_hash=False)

def cmd_rev_parse(args):
    if args.type:
        fmt = args.type.encode()
    else:
        fmt = None
    repo = repo_find()
    print(object_find(repo, args.name, fmt, follow=True))

def cmd_ls_files(args):
    repo = repo_find()
    index = index_read(repo)
    if args.verbose:
        print("Index file format v{}, containing {} entries.".format(index.version, len(index.entries)))
    for entry in index.entries:
        print(entry.name)
        if args.verbose:
            print("    {} with perms: {:o}".format(
                { 0b1000: "regular file",
                0b1010: "symlink",
                0b1110: "git link" }[entry.mode_type],
                entry.mode_perms))
            print("    on blob: {}".format(entry.sha))
            print("    created: {}.{}, modified: {}.{}".format(
                datetime.fromtimestamp(entry.ctime[0]),
                entry.ctime[1],
                datetime.fromtimestamp(entry.mtime[0]),
                entry.mtime[1]))
            print("    device: {}, inode: {}".format(entry.dev, entry.ino))
            print("    user: {} ({}), group: {} ({})".format(
                pwd.getpwuid(entry.uid).pw_name,
                entry.uid,
                grp.getgrgid(entry.gid).gr_name,
                entry.gid))
            print("    flags: stage={}, assume_valid={}".format(
                entry.flag_stage,
                entry.flag_assume_valid))

def cmd_check_ignore(args):
    repo = repo_find()
    rules = gitignore_read(repo)
    for path in args.path:
        if check_ignore(rules, path):
            print(path)

def cmd_status(_):
    repo = repo_find()
    index = index_read(repo)

    status_branch(repo)
    status_head_index(repo, index)
    print()
    status_index_worktree(repo, index)

def cmd_rm(args):
    repo = repo_find()
    rm(repo, args.path)

def cmd_add(args):
    repo = repo_find()
    add(repo, args.path)

def cmd_commit(args):
    repo = repo_find()
    index = index_read(repo)
    tree = tree_from_index(repo, index)
    commit = commit_create(repo,
                           tree,
                           object_find(repo, "HEAD"),
                           gitconfig_user_get(gitconfig_read()),
                           datetime.now(),
                           args.message)

    # Update HEAD
    active_branch = branch_get_active(repo)
    if active_branch:
        with open(repo_file(repo, os.path.join("refs/heads", active_branch)), "w") as fd:
            fd.write(commit + "\n")
    else:
        with open(repo_file(repo, "HEAD"), "w") as fd:
            fd.write("\n")

class GitRepository (object):
    """A git repository."""

    worktree = None
    gitdir = None
    conf = None

    def __init__(self, path, force=False):
        self.worktree = path
        self.gitdir = os.path.join(path, ".git")

        if not (force or os.path.isdir(self.gitdir)):
            raise Exception("Not a git repository. %s" % path)

        # Read configuration file in .git/config
        self.conf = configparser.ConfigParser()
        cf = repo_file(self, "config")

        if cf and os.path.exists(cf):
            self.conf.read([cf])
        elif not force:
            raise Exception("Configuration file missing.")
        
        if not force:
            vers = int(self.conf.get("core", "repositoryformatversion"))
            if vers != 0:
                raise Exception("Unsupported repositoryformatversion %s" % vers)

class GitObject (object):

    def __init__(self, data=None):
        if data != None:
            self.deserialize(data)
        else:
            self.init()

    def serialize():
        """This function MUST be implemented by subclasses.
        Converts a byte string into meaningful representation."""
        raise Exception("Unimplemented!")

    def deserialize():
        """This function MUST be implemented by subclasses.
        Inverse of serialize."""
        raise Exception("Unimplemented!")

    def init(self):
        pass

class GitBlob (GitObject):
    fmt=b'blob'

    def serialize(self):
        return self.blobdata

    def deserialize(self, data):
        self.blobdata = data

class GitCommit (GitObject):
    fmt = b'commit'

    def deserialize(self, data):
        self.kvlm = kvlm_parse(data)

    def serialize(self):
        return kvlm_serialize(self.kvlm)

    def init(self):
        self.kvlm = dict()

class GitTag (GitCommit):
    fmt = b'tag'

class GitTree (GitObject):
    fmt = b'tree'

    def deserialize(self, data):
        self.items = tree_parse(data)

    def serialize(self):
        return tree_serialize(self)

    def init(self):
        self.items = list()

class GitTreeLeaf (object):
    def __init__(self, mode, path, sha):
        self.mode = mode
        self.path = path
        self.sha = sha

class GitIndexEntry (object):
    def __init__(self, ctime=None, mtime=None, dev=None, ino=None, mode_type=None,
                mode_perms=None, uid=None, gid=None, fsize=None, sha=None,
                flag_assume_valid=None, flag_stage=None, name=None):
        # The last time a file's metadata changed.  This is a pair
        # (timestamp in seconds, nanoseconds)
        self.ctime = ctime
        # The last time a file's data changed.  This is a pair
        # (timestamp in seconds, nanoseconds)
        self.mtime = mtime
        # The ID of device containing this file
        self.dev = dev
        # The file's inode number
        self.ino = ino
        # The object type, either b1000 (regular), b1010 (symlink),
        # b1110 (gitlink).
        self.mode_type = mode_type
        # The object permissions, an integer.
        self.mode_perms = mode_perms
        # User ID of owner
        self.uid = uid
        # Group ID of ownner
        self.gid = gid
        # Size of this object, in bytes
        self.fsize = fsize
        # The object's SHA
        self.sha = sha
        self.flag_assume_valid = flag_assume_valid
        self.flag_stage = flag_stage
        # Name of the object (full path this time!)
        self.name = name

class GitIndex (object):
    version = None
    entries = []

    def __init__(self, version=2, entries=None):
        if not entries:
            entries = list()
        self.version = version
        self.entries = entries

class GitIgnore (object):
    absolute = None
    scoped = None

    def __init__(self, absolute, scoped):
        self.absolute = absolute
        self.scoped = scoped

def object_read(repo, sha):
    """Read object sha from Git repository repo.
    Return a GitObject whose type depends on the object."""

    path = repo_file(repo, "objects", sha[0:2], sha[2:])

    if not os.path.isfile(path):
        return None

    with open(path, "rb") as f:
        raw = zlib.decompress(f.read())

        # Read object type
        x = raw.find(b' ')
        fmt = raw[0:x]

        # Read and validate object size
        y = raw.find(b'\x00', x)
        size = int(raw[x:y].decode("ascii"))
        if size != len(raw) - y - 1:
            raise Exception("Malformed object {0}: bad length".format(sha))

        # Pick constructor
        match fmt:
            case b'commit'  : c=GitCommit
            case b'tree'    : c=GitTree
            case b'tag'     : c=GitTag
            case b'blob'    : c=GitBlob
            case _:
                raise Exception("Unknown type {0} for object {1}".format(fmt.decode("ascii"), sha))

        # Call constructor and return object
        return c(raw[y+1:])

def object_write(obj, repo=None):
    # Serialize object data
    data = obj.serialize()

    # Add header
    result = obj.fmt + b' ' + str(len(data)).encode() + b'\x00' + data

    # Compute hash
    sha =  hashlib.sha1(result).hexdigest()

    if repo:
        # Compute path
        path = repo_file(repo, "objects", sha[0:2], sha[2:], mkdir=True)

        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(zlib.compress(result))

    return sha

def cat_file(repo, obj, fmt=None):
    obj = object_read(repo, object_find(repo, obj, fmt=fmt))
    sys.stdout.buffer.write(obj.serialize())

def object_hash(f, fmt, repo=None):
    """Hash object. Write to repo if provided."""
    data = f.read()

    # Constructor based on fmt arg
    match fmt:
        case b'blob'    : obj=GitBlob(data)
        case b'commit'  : obj=GitCommit(data)
        case b'tag'     : obj=GitTag(data)
        case b'tree'    : obj=GitTree(data)
        case _:
            raise Exception("Unknown type %s" % fmt)

    return object_write(obj, repo)

def object_find(repo, name, fmt=None, follow=True):
    sha = object_resolve(repo, name)

    # Nothing matches
    if not sha:
        raise Exception("No such reference {0}.".format(name))

    # Multiple matches
    if len(sha) > 1:
        raise Exception("Ambiguous reference {0}: Candidates are:\n - {1}".format(name, "\n - ".join(sha)))

    sha = sha[0]

    if not fmt:
        return sha

    while True:
        obj = object_read(repo, sha)
        if obj.fmt == fmt:
            return sha
        if not follow:
            return None
        if obj.fmt == b'tag':
            sha = obj.kvlm[b'object'].decode("ascii")
        elif obj.fmt == b'commit' and fmt == b'tree':
            sha = obj.kvlm[b'tree'].decode("ascii")
        else:
            return None


def object_resolve(repo, name):
    """Resolve name to an object hash in repo.

        This function is aware of:

        - the HEAD literal
         - short and long hashes
         - tags
         - branches
         - remote branches"""
    candidates = list()
    hashRE = re.compile(r"^[0-9A-Fa-f]{4,40}$")

    # if name is empty stop
    if not name.strip():
        return None

    # Case 1: HEAD
    if name == "HEAD":
        return [ ref_resolve(repo, "HEAD") ]

    # Does this look like a hash or short hash (min 4 characters)?
    if hashRE.match(name):
        name = name.lower()
        prefix = name[0:2]
        path = repo_dir(repo, "objects", prefix, mkdir=False)
        if path:
            remainder = name[2:]
            for file in os.listdir(path):
                if file.startswith(remainder):
                    candidates.append(prefix + file)

    # Is it a reference?
    as_tag = ref_resolve(repo, "refs/tags/" + name)
    if as_tag:
        candidates.append(as_tag)

    as_branch = ref_resolve(repo, "refs/heads/" + name)
    if as_branch:
        candidates.append(as_branch)

    return candidates

def repo_path(repo, *path):
    """Compute path under repo's gitdir."""
    return os.path.join(repo.gitdir, *path)

def repo_file(repo, *path, mkdir=False):
    """Same as repo_path, but create dirname(*path) if absent."""
    if repo_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_path(repo, *path)
    
def repo_dir(repo, *path, mkdir=False):
    """Same as repo_path, but mkdir *path if absent if mkdir."""
    
    path = repo_path(repo, *path)

    if os.path.exists(path):
        if (os.path.isdir(path)):
            return path
        else:
            raise Exception("Not a directory %s" % path)
        
    if mkdir:
        os.makedirs(path)
        return path
    else:
        return None

def repo_create(path):
    """Create a new repository at path."""

    repo = GitRepository(path, True)

    # First ensure the path doesn't exist or is an empty dir
    if os.path.exists(repo.worktree):
        if not os.path.isdir(repo.worktree):
            raise Exception("%s is not a directory." % path)
        if os.path.exists(repo.gitdir) and os.listdir(repo.gitdir):
            raise Exception("%s is not empty." % path)
    else:
        os.makedirs(repo.worktree)
    
    assert repo_dir(repo, "branches", mkdir=True)
    assert repo_dir(repo, "objects", mkdir=True)
    assert repo_dir(repo, "refs", "tags", mkdir=True)
    assert repo_dir(repo, "refs", "heads", mkdir=True)

    # .git/description
    with open(repo_file(repo, "description"), "w") as f:
        f.write("Unnamed repository: edit this file 'description' to name the repository.\n")

    # .git/HEAD
    with open(repo_file(repo, "HEAD"), "w") as f:
        f.write("ref: refs/heads/master\n")
    
    # .git/config
    with open(repo_file(repo, "config"), "w") as f:
        config = repo_default_config()
        config.write(f)
    
    return repo

def repo_default_config():
    ret = configparser.ConfigParser()

    ret.add_section("core")
    ret.set("core", "repositoryformatversion", "0")
    ret.set("core", "filemode", "false")
    ret.set("core", "bare", "false")

    return ret

def repo_find(path=".", required=True):
    path = os.path.realpath(path)

    if os.path.isdir(os.path.join(path, ".git")):
        return GitRepository(path)

    # if you are here we recurse
    parent = os.path.realpath(os.path.join(path, ".."))

    if parent == path:
        # We are (g)root
        if required:
            raise Exception("No git directory.")
        else:
            return None

    # recursion!
    return repo_find(parent, required)

# KVLM = key value list with message
def kvlm_parse(raw, start=0, dct=None):
    # Allow existing dictonaries to be passed in or create a new one if this is the first call
    if not dct:
        dct = collections.OrderedDict()

    # Next space and new line
    spc = raw.find(b' ', start)
    nl = raw.find(b'\n', start)

    # Base case
    #print("Space: {0} New Line: {1} Start: {2} Dictionary:\n\t - {3}".format(spc, nl, start, "\n\t - ".join(dct)))
    if (spc < 0) or (nl < spc):
        assert nl == start
        dct[None] = raw[start+1:]
        return dct

    # Recursive case
    key = raw[start:spc]
    end = start
    while True:
        end = raw.find(b'\n', end+1)
        if raw[end + 1] != ord(' '):
            break

    value = raw[spc+1:end].replace(b'\n ', b'\n')
    if key in dct:
        if type(dct[key]) == list:
            dct[key].append(value)
        else:
            dct[key] = [ dct[key], value ]
    else:
        dct[key] = value

    return kvlm_parse(raw, start=end+1, dct=dct)

def kvlm_serialize(kvlm):
    retval = b''
    for key in kvlm.keys():
        # Skip the message
        if key == None:
            continue

        value = kvlm[key]

        # Convert value to a list
        if type(value) != list:
            value = [ value ]

        for item in value:
            retval += key + b' ' + (item.replace(b'\n', b'\n ')) + b'\n'

    # Add the message
    retval += b'\n' + kvlm[None] + b'\n'

    return retval

def log_graphviz(repo, sha, seen):
    if sha in seen:
        return
    seen.add(sha)

    commit = object_read(repo, sha)
    short_hash = sha[0:8]
    message = commit.kvlm[None].decode("utf8").strip()
    message = message.replace("\\", "\\\\")
    message = message.replace("\"", "\\\"")

    if b'\n' in message:
        message = message[:message.index(b'\n')]

    print("  c_{0} [label=\"{1}: {2}\"]".format(sha, sha[0:7], message))
    assert commit.fmt == b'commit'

    # No parents
    if not b'parent' in commit.kvlm.keys():
        return

    parents = commit.kvlm[b'parent']
    if type(parents) != list:
        parents = [ parents ]

    for parent in parents:
        parent = parent.decode("ascii")
        print("  c_{0} -> c_{1};".format(sha, parent))
        log_graphviz(repo, parent, seen)

def tree_parse_one(raw, start=0):
    # Make sure the mode is the correct length
    x = raw.find(b' ', start)
    assert (x - start == 5) or (x - start == 6)

    # Find the mode
    mode = raw[start:x]
    if len(mode) == 5:
        mode = b' ' + mode

    # Find the path
    y = raw.find(b'\x00', x)
    path = raw[x+1:y]

    # Find the hash and return the results
    sha = format(int.from_bytes(raw[y+1:y+21], "big"), "040x")
    return y+21, GitTreeLeaf(mode, path.decode("utf8"), sha)

def tree_parse(raw):
    pos = 0
    max = len(raw)
    retval = list()
    while pos < max:
        pos, data = tree_parse_one(raw, pos)
        retval.append(data)
    return retval

# Git needs trees to be sorted with a trailing / in the path if the path is a directory
# otherwise git will be angry
def tree_leaf_sort_key(leaf):
    if leaf.mode.startswith(b'10'):
        return leaf.path
    else:
        return leaf.path + "/"

def tree_serialize(obj):
    obj.items.sort(key=tree_leaf_sort_key)
    retval = b''
    for item in obj.items:
        retval += item.mode
        retval += b' '
        retval += item.path.encode("utf8")
        retval += b'\x00'
        sha = int(item.sha, 16)
        retval += sha.to_bytes(20, byteorder="big")
    return retval

def ls_tree(repo, ref, recursive=None, prefix=""):
    sha = object_find(repo, ref, fmt=b'tree')
    obj = object_read(repo, sha)
    for item in obj.items:
        if len(item.mode) == 5:
            type = item.mode[0:1]
        else:
            type = item.mode[0:2]

        match type:
            case b'04':
                type = "tree"
            case b'10':
                type = "blob"
            case b'12':
                type = "blob"
            case b'16':
                type = "commit"
            case _:
                raise Exception("Weird tree leaf mode {}".format(item.mode))

        if not (recursive and type == "tree"):
            print("{0} {1} {2}\t{3}".format(
                "0" * (6 - len(item.mode)) + item.mode.decode("ascii"),
                type,
                item.sha,
                os.path.join(prefix, item.path)))
        else:
            ls_tree(repo, item.sha, recursive, os.path.join(prefix, item.path))

def tree_checkout(repo, tree, path):
    for item in tree.items:
        obj = object_read(repo, item.sha)
        dest = os.path.join(path, item.path)

        if obj.fmt == b'tree':
            os.mkdir(dest)
            tree_checkout(repo, obj, dest)
        elif obj.fmt == b'blob':
            # ADD SYMLINK SUPPORT HERE LATER ON
            with open(dest, 'wb') as f:
                f.write(obj.blobdata)

def ref_resolve(repo, ref):
    path = repo_file(repo, ref)
    if not os.path.isfile(path):
        return None
    with open(path, 'r') as fp:
        # Skip trailing newline
        data = fp.read()[:-1]
    if data.startswith("ref: "):
        return ref_resolve(repo, data[5:])
    else:
        return data

def ref_list(repo, path=None):
    if not path:
        path = repo_dir(repo, "refs")
    retval = collections.OrderedDict()
    for file in sorted(os.listdir(path)):
        can = os.path.join(path, file)
        if os.path.isdir(can):
            retval[file] = ref_list(repo, can)
        else:
            retval[file] = ref_resolve(repo, can)
    return retval

def show_ref(repo, refs, with_hash=True, prefix=""):
    for key, value in refs.items():
        if type(value) == str:
            print("{0}{1}{2}".format(
                value + " " if with_hash else "",
                prefix + "/" if prefix else "",
                key))
        else:
            show_ref(repo, value, with_hash=with_hash, prefix="{0}{1}{2}".format(prefix, "/" if prefix else "", key))

def tag_create(repo, name, ref, create_tag_object=False):
    sha = object_find(repo, ref)
    if create_tag_object:
        tag = GitTag(repo)
        tag.kvlm = collections.OrderedDict()
        tag.kvlm[b'object'] = sha.encode()
        tag.kvlm[b'type'] = b'commit'
        tag.kvlm[b'tag'] = name.encode()
        # For now keep the tagger generic (can fix later)
        tag.kvlm[b'tagger'] = b'Autumn <autumn@staszeski.com>'
        tag.kvlm[None] = b'A tag generated by wyag! We can\'t customize messages yet'
        tag_sha = object_write(tag)
        ref_create(repo, "tags/" + name, tag_sha)
    else:
        ref_create(repo, "tags/" + name, sha)

def ref_create(repo, ref_name, sha):
    with open(repo_file(repo, "refs/" + ref_name), 'w') as fp:
        fp.write(sha + "\n")

def index_read(repo):
    index_file = repo_file(repo, "index")

    # If the repo is new create an empty index
    if not os.path.exists(index_file):
        return GitIndex()

    with open(index_file, 'rb') as f:
        raw =  f.read()

    # Check header, signature, and version
    header = raw[:12]
    signature = raw[:4]
    assert signature == b"DIRC"
    version = int.from_bytes(header[4:8], "big")
    assert version == 2, "wyag only supports version 2"
    count = int.from_bytes(header[8:12], "big")

    # Now get the actual data
    entries = list()
    content = raw[12:]
    index = 0
    for i in range(0, count):
        # Read ctime and mtime as unix and nanoseconds for precision
        ctime_s =  int.from_bytes(content[index:index+4], "big")
        ctime_ns =  int.from_bytes(content[index+4:index+8], "big")
        mtime_s =  int.from_bytes(content[index+8:index+12], "big")
        mtime_ns =  int.from_bytes(content[index+12:index+16], "big")

        # Device ID and Inode
        dev = int.from_bytes(content[index+16:index+20], "big")
        ino = int.from_bytes(content[index+20:index+24], "big")

        # Ignored
        unused = int.from_bytes(content[index+24:index+26], "big")
        assert 0 == unused

        # Mode
        mode = int.from_bytes(content[index+26:index+28], "big")
        mode_type = mode >> 12
        assert mode_type in [0b1000, 0b1010, 0b1110]
        mode_perms = mode & 0b0000000111111111

        # User ID, Group ID, and Size
        uid = int.from_bytes(content[index+28:index+32], "big")
        gid = int.from_bytes(content[index+32:index+36], "big")
        fsize = int.from_bytes(content[index+36:index+40], "big")

        # SHA as a lowercase hex string
        sha = format(int.from_bytes(content[index+40:index+60], "big"), "040x")

        # Flags
        flags = int.from_bytes(content[index+60:index+62], "big")
        flag_assume_valid = (flags & 0b1000000000000000) != 0
        flag_extended = (flags & 0b0100000000000000) != 0
        assert not flag_extended
        flag_stage =  flags & 0b0011000000000000
        name_length = flags & 0b0000111111111111

        # Update index and read name
        index += 62
        if name_length < 0xFFF:
            assert content[index:index+name_length]
            raw_name = content[index:index+name_length]
            index += name_length + 1
        else:
            print("Notice: name is 0x{:X} bytes long.".format(name_length))
            # Likely needs to be fixed
            null_index = content.find(b'\x00', index + 0xFFF)
            raw_name = content[index:null_index]
            index = null_index + 1
        name = raw_name.decode("utf8")
        index = 8*ceil(index/8) # Round to a multiple of 8 to skip padding

        entries.append(GitIndexEntry(ctime=(ctime_s, ctime_ns),
                                        mtime=(mtime_s, mtime_ns),
                                        dev=dev,
                                        ino=ino,
                                        mode_type=mode_type,
                                        mode_perms=mode_perms,
                                        uid=uid,
                                        gid=gid,
                                        fsize=fsize,
                                        sha=sha,
                                        flag_assume_valid=flag_assume_valid,
                                        flag_stage=flag_stage,
                                        name=name))

    return GitIndex(version=version, entries=entries)

def gitignore_parse1(raw):
    raw = raw.strip()
    if not raw or raw[0] == "#":
        return None
    elif raw[0] == "!":
        return (raw[1:], False)
    elif raw[0] == "\\":
        return (raw[1:], True)
    else:
        return (raw, True)

def gitignore_parse(lines):
    retval = list()
    for line in lines:
        parsed = gitignore_parse1(line)
        if parsed:
            retval.append(parsed)
    return retval

def gitignore_read(repo):
    retval = GitIgnore(absolute=list(), scoped=dict())

    # Check exclude file in .git
    repo_file = os.path.join(repo.gitdir, "info/exclude")
    if os.path.exists(repo_file):
        with open(repo_file, "r") as f:
            retval.absolute.append(gitignore_parse(f.readlines()))

    # Find global file
    if "XDG_CONFIG_HOME" in os.environ:
        config_home = os.environ["XDG_CONFIG_HOME"]
    else:
        config_home = os.path.expanduser("~/.config")
    global_file = os.path.join(config_home, "git/ignore")
    if os.path.exists(global_file):
        with open(global_file, "r") as f:
            retval.absolute.append(gitignore_parse(f.readlines()))

    # Check for .gitignore files in the index
    index = index_read(repo)
    for entry in index.entries:
        if entry.name == ".gitignore" or entry.name.endswith("/.gitignore"):
            dir_name = os.path.dirname(entry.name)
            contents = object_read(repo, entry.sha)
            lines = contents.blobdata.decode("utf8").splitlines()
            retval.scoped[dir_name] = gitignore_parse(lines)

    return retval

def check_ignore1(rules, path):
    result = None
    for (pattern, value) in rules:
        if fnmatch(path, pattern):
            result = value
    return result

def check_ignore_scoped(rules, path):
    parent = os.path.dirname(path)
    while True:
        if parent in rules:
            result = check_ignore1(rules[parent], path)
            if result != None:
                return result
        if parent == "":
            break
        parent = os.path.dirname(parent)
    return None

def check_ignore_absolute(rules, path):
    parent = os.path.dirname(path)
    for ruleset in rules:
        result = check_ignore1(ruleset, path)
        if result != None:
            return result
    return False

def check_ignore(rules, path):
    if os.path.isabs(path):
        raise Exception("This function requires path to be relative to the repository's root.")
    result = check_ignore_scoped(rules.scoped, path)
    if result != None:
        return result
    return check_ignore_absolute(rules.absolute, path)

def branch_get_active(repo):
    with open(repo_file(repo, "HEAD"), "r") as f:
        head = f.read()

    if head.startswith("ref: refs/heads/"):
        return head[16:-1]
    else:
        return False

def status_branch(repo):
    branch = branch_get_active(repo)
    if branch:
        print("On branch {}.".format(branch))
    else:
        print("HEAD detached at {}.".format(object_find(repo, "HEAD")))

def tree_to_dict(repo, ref, prefix=""):
    retval = dict()
    tree_sha = object_find(repo, ref, fmt=b"tree")
    tree = object_read(repo, tree_sha)

    for leaf in tree.items:
        full_path = os.path.join(prefix, leaf.path)
        is_subtree = leaf.mode.startswith(b'04')
        if is_subtree:
            retval.update(tree_to_dict(repo, leaf.sha, full_path))
        else:
            retval[full_path] = leaf.sha
    return retval

def status_head_index(repo, index):
    print("Changes to be committed:")
    head = tree_to_dict(repo, "HEAD")
    for entry in index.entries:
        if entry.name in head:
            if head[entry.name] != entry.sha:
                print("\033[32m\tmodified:\t", entry.name, "\033[0m")
            del head[entry.name]
        else:
            print("\033[32m\tadded:\t\t", entry.name, "\033[0m")
    for entry in head.keys():
        print("\033[32m\tdeleted:\t", entry.name, "\033[0m")

def status_index_worktree(repo, index):
    print("Changes not staged for commit:")
    ignore = gitignore_read(repo)
    gitdir_prefix = repo.gitdir + os.path.sep
    all_files = list()

    # Walk the filesystem
    for (root, _, files) in os.walk(repo.worktree, True):
        if root == repo.gitdir or root.startswith(gitdir_prefix):
            continue
        else:
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, repo.worktree)
                all_files.append(rel_path)

    # Compare real files to cached versions
    for entry in index.entries:
        full_path = os.path.join(repo.worktree, entry.name)

        # If the file is in the index but doesn't exist, it was deleted
        if not os.path.exists(full_path):
            print("\033[31m\tdeleted:\t", entry.name, "\033[0m")
        else:
            stat = os.stat(full_path)

            # Metadata time!
            ctime_ns = entry.ctime[0] * 10**9 + entry.ctime[1]
            mtime_ns = entry.mtime[0] * 10**9 + entry.mtime[1]
            if (stat.st_ctime_ns != ctime_ns) or (stat.st_mtime_ns != mtime_ns):
                # If the time is different, look closer
                with open(full_path, "rb") as fd:
                    new_sha = object_hash(fd, b"blob", None)
                    same = entry.sha == new_sha
                    if not same:
                        print("\033[31m\tmodified:\t", entry.name, "\033[0m")
        if entry.name in all_files:
            all_files.remove(entry.name)

    print()
    print("Untracked files:")
    for file in all_files:
        if not check_ignore(ignore, file):
            print("\033[31m\t", file, "\033[0m")

def index_write(repo, index):
    with open(repo_file(repo, "index"), "wb") as f:
        # Header
        f.write(b"DIRC")
        f.write(index.version.to_bytes(4, "big"))
        f.write(len(index.entries).to_bytes(4, "big"))

        # Entries
        idx = 0
        for entry in index.entries:
            f.write(entry.ctime[0].to_bytes(4, "big"))
            f.write(entry.ctime[1].to_bytes(4, "big"))
            f.write(entry.mtime[0].to_bytes(4, "big"))
            f.write(entry.mtime[1].to_bytes(4, "big"))
            f.write(entry.dev.to_bytes(4, "big"))
            f.write(entry.ino.to_bytes(4, "big"))

            # Mode
            mode = (entry.mode_type << 12) | entry.mode_perms
            f.write(mode.to_bytes(4, "big"))

            f.write(entry.uid.to_bytes(4, "big"))
            f.write(entry.gid.to_bytes(4, "big"))
            f.write(entry.fsize.to_bytes(4, "big"))
            f.write(int(entry.sha, 16).to_bytes(20, "big"))

            flag_assume_valid = 0x1 << 15 if entry.flag_assume_valid else 0

            name_bytes = entry.name.encode("utf8")
            bytes_len = len(name_bytes)
            if bytes_len >= 0xFFF:
                name_length = 0xFFF
            else:
                name_length = bytes_len

            f.write((entry.flag_assume_valid | entry.flag_stage | name_length).to_bytes(2, "big"))

            # Name and Null
            f.write(name_bytes)
            f.write((0).to_bytes(1, "big"))

            # Update idx
            idx += 62 + len(name_bytes) + 1
            if idx % 8 != 0:
                padding = 8 - (idx % 8)
                f.write((0).to_bytes(padding, "big"))
                idx += padding

def rm(repo, paths, delete=True, skip_missing=False):
    index = index_read(repo)
    worktree = repo.worktree + os.sep

    # Make paths absolute
    abspaths = list()
    for path in paths:
        abspath = os.path.abspath(path)
        if abspath.startswith(worktree):
            abspaths.append(abspath)
        else:
            raise Exception("Cannot remove paths outside of the worktree: {}".format(path))

    kept_entries = list()
    remove = list()

    for entry in index.entries:
        full_path = os.path.join(repo.worktree, entry.name)
        if full_path in abspaths:
            remove.append(full_path)
            abspaths.remove(full_path)
        else:
            kept_entries.append(entry)

    if len(abspaths) > 0 and not skip_missing:
        raise Exception("Cannot skip paths not in the index: {}".format(abspaths))

    if delete:
        for path in paths:
            os.unlink(path)

    index.entries = kept_entries
    index_write(repo, index)

def add(repo, paths, delete=True, skip_missing=False):
    rm(repo, paths, delete=False, skip_missing=True)
    worktree = repo.worktree + os.sep

    # Convert paths to pairs
    clean_paths = list()
    for path in paths:
        abspath = os.path.abspath(path)
        if not (abspath.startswith(worktree) and os.path.isfile(abspath)):
            raise Exception("Not a file or outside the worktree: {}".format(path))
        relpath = os.path.relpath(abspath, repo.worktree)
        clean_paths.append((abspath, relpath))

    # Read the index and modify it (this is suboptimal)
    index = index_read(repo)
    for (abspath, relpath) in clean_paths:
        with open(abspath, "rb") as fd:
            sha = object_hash(fd, b"blob", repo)

        # Get created and modified times
        stat = os.stat(abspath)
        ctime_s = int(stat.st_ctime)
        ctime_ns = stat.st_ctime_ns % 10**9
        mtime_s = int(stat.st_mtime)
        mtime_ns = stat.st_mtime_ns % 10**9

        entry = GitIndexEntry(ctime=(ctime_s, ctime_ns),
                              mtime=(mtime_s, mtime_ns),
                              dev=stat.st_dev,
                              ino=stat.st_ino,
                              mode_type=0b1000,
                              mode_perms=0o644,
                              uid=stat.st_uid,
                              gid=stat.st_gid,
                              fsize=stat.st_size,
                              sha=sha,
                              flag_assume_valid=False,
                              flag_stage=False,
                              name=relpath)
        index.entries.append(entry)
    index_write(repo, index)

def gitconfig_read():
    xdg_config_home = os.environ["XDG_CONFIG_HOME"] if "XDG_CONFIG_HOME" in os.environ else "~/.config"
    config_files = [
        os.path.expanduser(os.path.join(xdg_config_home, "git/config")),
        os.path.expanduser("~/.gitconfig")
    ]
    config = configparser.ConfigParser()
    config.read(config_files)
    return config

def gitconfig_user_get(config):
    if "user" in config:
        if "name" in config["user"] and "email" in config["user"]:
            return "{} <{}>".format(config["user"]["name"], config["user"]["email"])
    return None

def tree_from_index(repo, index):
    contents = dict()
    contents[""] = list()

    # First we convert the index into a dictionary
    for entry in index.entries:
        dirname = os.path.dirname(entry.name)

        # Create a key for every directory
        key = dirname
        while key != "":
            if not key in contents:
                contents[key] = list()
            key = os.path.dirname(key)

        # Store the entry for now
        contents[dirname].append(entry)

    # Sort keys by length
    sorted_paths = sorted(contents.keys(), key=len, reverse=True)

    # Iterate over sorted paths and track root hash
    sha = None
    for path in sorted_paths:
        tree = GitTree()
        for entry in contents[path]:
            # Either a GitIndexEntry or a Tree
            if isinstance(entry, GitIndexEntry):
                # Transcode the mode
                leaf_mode = "{:02o}{:04o}".format(entry.mode_type, entry.mode_perms).encode("ascii")
                leaf = GitTreeLeaf(mode=leaf_mode, path=os.path.basename(entry.name), sha=entry.sha)
            else:
                leaf = GitTreeLeaf(mode=b"040000", path=entry[0], sha=entry[1])
            tree.items.append(leaf)

        # Add the new tree as a pair of (basename, SHA)
        sha = object_write(tree, repo)
        parent = os.path.dirname(path)
        base = os.path.basename(path)
        contents[parent].append((base, sha))
    return sha

def commit_create(repo, tree, parent, author, timestamp, message):
    commit = GitCommit()
    commit.kvlm[b"tree"] = tree.encode("ascii")
    if parent:
        commit.kvlm[b"parent"] = parent.encode("ascii")

    # Format timezone
    offset = int(timestamp.astimezone().utcoffset().total_seconds())
    hours = offset // 3600
    minutes = (offset%3600) // 60
    tz = "{}{:02}{:02}".format("+" if offset > 0 else "-", hours, minutes)

    author = author + timestamp.strftime(" % ") + tz

    commit.kvlm[b"author"] = author.encode("utf8")
    commit.kvlm[b"committer"] = author.encode("utf8")
    commit.kvlm[None] = message.encode("utf8")

    return object_write(commit, repo)