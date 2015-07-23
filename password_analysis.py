import enchant
import sys
import re, operator, string
from optparse import OptionParser, OptionGroup
import time

class Analyze:
    def __init__(self):
        self.outFile = None

        # Filters
        self.minlen   = None
        self.maxlen   = None
        self.masks = None
        self.charsets    = None
        self.debug = True

        # dictionaries
        self.length = dict()
        self.masks_dict = dict()
        self.moreMasks_dict = dict()
        self.charactersets_dict = dict()

        self.filter_counter = 0
        self.total_counter = 0

        # Minimum password complexity counters
        self.mindigit   = None
        self.minupper   = None
        self.minlower   = None
        self.minspecial = None

        self.maxdigit   = None
        self.maxupper   = None
        self.maxlower   = None
        self.maxspecial = None

	#Other Variables
	self.usrname = None
	self.inDict = None

    def password_parser_helper(self, password):

        # Password length
        pass_length = len(password)

        # Initialize counters
        digit = 0
        lower = 0
        upper = 0
        special = 0

        simplemask = list()
        mask_str = ""

        # Detect masks
        for letter in password:
 
            if letter in string.digits:
                digit += 1
                mask_str += "D"
                if not simplemask or not simplemask[-1] == 'D': simplemask.append('D')

            elif letter in string.lowercase:
                lower += 1
                mask_str += "L"
                if not simplemask or not simplemask[-1] == 'L': simplemask.append('L')


            elif letter in string.uppercase:
                upper += 1
                mask_str += "U"
                if not simplemask or not simplemask[-1] == 'U': simplemask.append('U')

            else:
                special += 1
                mask_str += "S"
                if not simplemask or not simplemask[-1] == 'S': simplemask.append('S')


        # String representation of masks
        simplemask_string = ''.join(simplemask) if len(simplemask) <= 3 else 'Others'

        # Policy
        policy = (digit,lower,upper,special)

        # Determine character-set
        if   digit and not lower and not upper and not special: charset = 'Numeric'
        elif not digit and lower and not upper and not special: charset = 'LowerCase'
        elif not digit and not lower and upper and not special: charset = 'UpperCase'
        elif not digit and not lower and not upper and special: charset = 'Special'

        elif not digit and lower and upper and not special:     charset = 'LowerCase & UpperCase'
        elif digit and lower and not upper and not special:     charset = 'LowerCase & Numeric'
        elif digit and not lower and upper and not special:     charset = 'UpperCase & Numeric'
        elif not digit and lower and not upper and special:     charset = 'LowerCase & Special'
        elif not digit and not lower and upper and special:     charset = 'UpperCase & Special'
        elif digit and not lower and not upper and special:     charset = 'Special & Numeric'

        elif not digit and lower and upper and special:         charset = 'LowerCase,UpperCase & Special'
        elif digit and not lower and upper and special:         charset = 'UpperCase, Numeric & Special'
        elif digit and lower and not upper and special:         charset = 'LowerCase,Numeric & Special'
        elif digit and lower and upper and not special:         charset = 'LowerCase, UpperCase & Numeric'
        else:                                                   charset = 'All'

        return (pass_length, charset, simplemask_string, mask_str, policy)

    def password_parser(self, filename):
        """ Generate password statistics. """
        d=enchant.Dict("en_US")
        f = open(filename,'r')

        usrname=0
        inDict=0
        for password in f:

	    password12 = ' '.join([segment for segment in password.split()])
	    password1 = password12.split(' ')
            password = password1[1].rstrip('\r\n')
            
            if len(password) == 0: continue
            if password1[0] in password:
                usrname=usrname+1
            self.total_counter += 1  
            if d.check(password):
                inDict=inDict+1


            (pass_length,characterset,simplemask,advancedmask, policy) = self.password_parser_helper(password)
            (digit,lower,upper,special) = policy

            if (self.charsets == None    or characterset in self.charsets) and \
               (self.masks == None or simplemask in self.masks) and \
               (self.maxlen == None   or pass_length <= self.maxlen) and \
               (self.minlen == None   or pass_length >= self.minlen):

                self.filter_counter += 1

                if self.mindigit == None or digit < self.mindigit: self.mindigit = digit
                if self.maxdigit == None or digit > self.maxdigit: self.maxdigit = digit

                if self.minupper == None or upper < self.minupper: self.minupper = upper
                if self.maxupper == None or upper > self.maxupper: self.maxupper = upper

                if self.minlower == None or lower < self.minlower: self.minlower = lower
                if self.maxlower == None or lower > self.maxlower: self.maxlower = lower

                if self.minspecial == None or special < self.minspecial: self.minspecial = special
                if self.maxspecial == None or special > self.maxspecial: self.maxspecial = special

                if pass_length in self.length:
                    self.length[pass_length] += 1
                else:
                    self.length[pass_length] = 1

                if characterset in self.charactersets_dict:
                    self.charactersets_dict[characterset] += 1
                else:
                    self.charactersets_dict[characterset] = 1

                if simplemask in self.masks_dict:
                    self.masks_dict[simplemask] += 1
                else:
                    self.masks_dict[simplemask] = 1

                if advancedmask in self.moreMasks_dict:
                    self.moreMasks_dict[advancedmask] += 1
                else:
                    self.moreMasks_dict[advancedmask] = 1
        self.usrname=usrname
        self.inDict=inDict

        f.close()

    def password_analysis(self):

        print "Analyzing %d%% (%d/%d) of passwords" % (self.filter_counter*100/self.total_counter, self.filter_counter, self.total_counter)
        print "\nLength:"
        for (length,count) in sorted(self.length.iteritems(), key=operator.itemgetter(1), reverse=True):
            print "%25d: %02d%% (%d)" % (length, count*100/self.filter_counter, count)

        print "\nCharacter-set:"
        for (char,count) in sorted(self.charactersets_dict.iteritems(), key=operator.itemgetter(1), reverse=True):
            print " %25s: %02d%% (%d)" % (char, count*100/self.filter_counter, count)

        print "\n Complexity of Password Dataset:"
        print "                       Digit: min(%s) max(%s)" % (self.mindigit, self.maxdigit)
        print "                   LowerCase: min(%s) max(%s)" % (self.minlower, self.maxlower)
        print "                   UpperCase: min(%s) max(%s)" % (self.minupper, self.maxupper)
        print "                     Special: min(%s) max(%s)" % (self.minspecial, self.maxspecial)

	print "\nD - Digit, L- Lower Case, U- Upper Case, S- Special Characters"	
        print "\n Simple Masks:"
        for (simplemask,count) in sorted(self.masks_dict.iteritems(), key=operator.itemgetter(1), reverse=True):
            print " %25s: %02d%% (%d)" % (simplemask, count*100/self.filter_counter, count)

        print "\n Advanced Masks:"
        for (advancedmask,count) in sorted(self.moreMasks_dict.iteritems(), key=operator.itemgetter(1), reverse=True):
            if count*100/self.filter_counter > 0:
                print " %25s: %02d%% (%d)" % (advancedmask, count*100/self.filter_counter, count)

            if self.outFile:
                self.outFile.write("%s,%d\n" % (advancedmask,count))
	
	print "\n Passwords that match usernames:"
	print "\t%s" % (self.usrname)

	print "\n Passwords that are words in the English Dictionary:"
	print "\t%s" % (self.inDict)

if __name__ == "__main__":

    parser = OptionParser("%prog [options] passwords.txt\n\nType --help for more options")

    filters = OptionGroup(parser, "Password Filters")
    filters.add_option("--minlen", dest="minlen", type="int", metavar="8", help="Minimum password length")
    filters.add_option("--maxlen", dest="maxlen", type="int", metavar="8", help="Maximum password length")
    filters.add_option("--charset", dest="charsets", help="Password charset filter (comma separated)", metavar="loweralpha,numeric")
    filters.add_option("--simplemask", dest="masks",help="Password mask filter (comma separated)", metavar="stringdigit,allspecial")
    parser.add_option_group(filters)

    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.error("no passwords file specified")
        exit(1)

    print "Analyzing passwords in [%s]" % args[0]

    analyze = Analyze()

    if not options.minlen   == None: analyze.minlen   = options.minlen
    if not options.maxlen   == None: analyze.maxlen   = options.maxlen
    if not options.charsets    == None: analyze.charsets    = [x.strip() for x in options.charsets.split(',')]
    if not options.masks == None: analyze.masks = [x.strip() for x in options.masks.split(',')]

    analyze.password_parser(args[0])
    analyze.password_analysis()
