#include <bfd.h>
#include <dis-asm.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <libiberty.h>

typedef unsigned int dword;

dword SIZE = 0;
dword START = 0x100000; // 1 MiB.

struct bfd *     abfd  = NULL;
disassemble_info dinfo = {0};

/*
 * Temporary hack to signal when disassembling should stop.
 */
static bool stop_disassembling = FALSE;

/* Categories.  */

enum {
  /* In C99 */
  _sch_isblank  = 0x0001,       /* space \t */
  _sch_iscntrl  = 0x0002,       /* nonprinting characters */
  _sch_isdigit  = 0x0004,       /* 0-9 */
  _sch_islower  = 0x0008,       /* a-z */
  _sch_isprint  = 0x0010,       /* any printing character including ' ' */
  _sch_ispunct  = 0x0020,       /* all punctuation */
  _sch_isspace  = 0x0040,       /* space \t \n \r \f \v */
  _sch_isupper  = 0x0080,       /* A-Z */
  _sch_isxdigit = 0x0100,       /* 0-9A-Fa-f */

  /* Extra categories useful to cpplib.  */
  _sch_isidst   = 0x0200,       /* A-Za-z_ */
  _sch_isvsp    = 0x0400,       /* \n \r */
  _sch_isnvsp   = 0x0800,       /* space \t \f \v \0 */

  /* Combinations of the above.  */
  _sch_isalpha  = _sch_isupper|_sch_islower,    /* A-Za-z */
  _sch_isalnum  = _sch_isalpha|_sch_isdigit,    /* A-Za-z0-9 */
  _sch_isidnum  = _sch_isidst|_sch_isdigit,     /* A-Za-z0-9_ */
  _sch_isgraph  = _sch_isalnum|_sch_ispunct,    /* isprint and not space */
  _sch_iscppsp  = _sch_isvsp|_sch_isnvsp,       /* isspace + \0 */
  _sch_isbasic  = _sch_isprint|_sch_iscppsp     /* basic charset of ISO C
                                                   (plus ` and @)  */
};

/* Shorthand */
#define bl _sch_isblank
#define cn _sch_iscntrl
#define di _sch_isdigit
#define is _sch_isidst
#define lo _sch_islower
#define nv _sch_isnvsp
#define pn _sch_ispunct
#define pr _sch_isprint
#define sp _sch_isspace
#define up _sch_isupper
#define vs _sch_isvsp
#define xd _sch_isxdigit

/* Masks.  */
#define L  (const unsigned short) (lo|is   |pr) /* lower case letter */
#define XL (const unsigned short) (lo|is|xd|pr) /* lowercase hex digit */
#define U  (const unsigned short) (up|is   |pr) /* upper case letter */
#define XU (const unsigned short) (up|is|xd|pr) /* uppercase hex digit */
#define D  (const unsigned short) (di   |xd|pr) /* decimal digit */
#define P  (const unsigned short) (pn      |pr) /* punctuation */
#define _  (const unsigned short) (pn|is   |pr) /* underscore */

#define C  (const unsigned short) (         cn) /* control character */
#define Z  (const unsigned short) (nv      |cn) /* NUL */
#define M  (const unsigned short) (nv|sp   |cn) /* cursor movement: \f \v */
#define V  (const unsigned short) (vs|sp   |cn) /* vertical space: \r \n */
#define T  (const unsigned short) (nv|sp|bl|cn) /* tab */
#define S  (const unsigned short) (nv|sp|bl|pr) /* space */

const unsigned short _sch_istable[256] =
{
  Z,  C,  C,  C,   C,  C,  C,  C,   /* NUL SOH STX ETX  EOT ENQ ACK BEL */
  C,  T,  V,  M,   M,  V,  C,  C,   /* BS  HT  LF  VT   FF  CR  SO  SI  */
  C,  C,  C,  C,   C,  C,  C,  C,   /* DLE DC1 DC2 DC3  DC4 NAK SYN ETB */
  C,  C,  C,  C,   C,  C,  C,  C,   /* CAN EM  SUB ESC  FS  GS  RS  US  */
  S,  P,  P,  P,   P,  P,  P,  P,   /* SP  !   "   #    $   %   &   '   */
  P,  P,  P,  P,   P,  P,  P,  P,   /* (   )   *   +    ,   -   .   /   */
  D,  D,  D,  D,   D,  D,  D,  D,   /* 0   1   2   3    4   5   6   7   */
  D,  D,  P,  P,   P,  P,  P,  P,   /* 8   9   :   ;    <   =   >   ?   */
  P, XU, XU, XU,  XU, XU, XU,  U,   /* @   A   B   C    D   E   F   G   */
  U,  U,  U,  U,   U,  U,  U,  U,   /* H   I   J   K    L   M   N   O   */
  U,  U,  U,  U,   U,  U,  U,  U,   /* P   Q   R   S    T   U   V   W   */
  U,  U,  U,  P,   P,  P,  P,  _,   /* X   Y   Z   [    \   ]   ^   _   */
  P, XL, XL, XL,  XL, XL, XL,  L,   /* `   a   b   c    d   e   f   g   */
  L,  L,  L,  L,   L,  L,  L,  L,   /* h   i   j   k    l   m   n   o   */
  L,  L,  L,  L,   L,  L,  L,  L,   /* p   q   r   s    t   u   v   w   */
  L,  L,  L,  P,   P,  P,  P,  C,   /* x   y   z   {    |   }   ~   DEL */

  /* high half of unsigned char is locale-specific, so all tests are
     false in "C" locale */
  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,

  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
};

/*
 * Gets path to currently running executable.
 */
bool get_target_path(char * target_path, size_t size)
{
    char *   path;
    ssize_t len;

    pid_t pid = getpid();
    sprintf(target_path, "/proc/%d/exe", (int)pid );

    path = strdup(target_path);
    len  = readlink(path, target_path, size);

    target_path[len] = '\0';
    free(path);
    return TRUE;
}

/*
 * libopcodes appends spaces on the end of some instructions so for
 * comparisons, we want to strip those first.
 */
void strip_tail(char * str, unsigned int size)
{
    int i;
    for(i = 0; i < size; i++) {
        if(!isgraph(str[i])) {
            str[i] = '\0';
            break;
        }
    }
}

/*
 * Checks whether the current instruction will cause the control flow to not
 * proceed to the linearly subsequent instruction (e.g. ret, jmp, etc.)
 */
bool breaks_control_flow(char * str)
{
    if(abfd->arch_info->bits_per_address == 64) {
        if(strcmp(str, "retq") == 0) {
            return TRUE;
        }
    } else {
        if(strcmp(str, "ret") == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

bool begin_insn = true;
bool first_time = true;
bool label_insn = true;
FILE* ipass = NULL; // two passes, to sort labels.
FILE* opass = NULL;

/*
 * Used as a callback for libopcodes so we can do something useful with the
 * disassembly. Currently this just outputs to stdout.
 */
int custom_fprintf(void * stream, const char * format, ...)
{
    /* silly amount */
   char    str[128] = {0};
   int rv;
   va_list args;

   va_start(args, format);
   rv = vsnprintf(str, ARRAY_SIZE(str) - 1, format, args);
   va_end(args);

   if( stop_disassembling ) return rv;

   //puts(str); // excess newlines.
   int sis = 0;
   if( begin_insn )
   {
      fprintf( opass, "\t\t" ); // no labels to the left here
      begin_insn = false;
   }
   for(; sis < strlen( str ); ++sis )
   {
      fprintf( opass, "%c", str[ sis ] );
   }
   strip_tail(str, ARRAY_SIZE(str));
   //puts(str); // excess newlines.

   if(breaks_control_flow(str)) {
       puts("Stopped disassembly");
       stop_disassembling = TRUE;
   }
/*
   if( false && dinfo.insn_info_valid )
   {
      switch(dinfo.insn_type)
      {
            case dis_noninsn:
                printf("not an instruction\n");
                break;
            case dis_nonbranch:
                printf("not a branch\n");
                break;
            case dis_branch:
                printf("is a branch\n");
                break;
            case dis_condbranch:
                printf("is a conditional branch\n");
                break;
            case dis_jsr:
                printf("jump to subroutine\n");
                break;
            case dis_condjsr:
                printf("conditional jump to subroutine\n");
                break;
            case dis_dref:
                printf("data reference in instruction\n");
                break;
            case dis_dref2:
                printf("two data references in instruction\n");
                break;
            default:
                printf("not enumerated\n");
                break;
      }
   } else
   {
//insn_type is not filled in: https://stackoverflow.com/questions/9132006/how-to-get-instruction-information-from-libopcodes
//        printf("insn_info not valid\n");
   }
*/
   return rv;
}

enum bfd_architecture
get_arch (const bfd *abfd)
{
  return abfd->arch_info->arch;
}

unsigned long
get_mach (const bfd *abfd)
{
  return abfd->arch_info->mach;
}

disassembler_ftype init_disasm(struct bfd * abfd, disassemble_info * dinfo)
{
    /* Override the stream the disassembler outputs to */
   //printf( "@" );  fflush( stdout );
   init_disassemble_info(dinfo, NULL, custom_fprintf);
   //printf( "a" );  fflush( stdout );
   dinfo->flavour = bfd_get_flavour(abfd);
   dinfo->arch    = get_arch(abfd);
   dinfo->mach    = get_mach(abfd);
   dinfo->endian  = abfd->xvec->byteorder;
   disassemble_init_for_target(dinfo);
   //printf( "b" );  fflush( stdout );
   return disassembler(bfd_arch_i386, false, bfd_mach_i386_i386_intel_syntax, abfd);
}

//extern disassembler_ftype disassembler (enum bfd_architecture arc,
//                                        bfd_boolean big, unsigned long mach,
//                                        bfd *abfd);

/*
 * Loads section and fills in dinfo accordingly. Since this function allocates
 * memory in dinfo->buffer, callers need to call free once they are finished.
 */
bool load_section(bfd * abfd, disassemble_info * dinfo, asection * s)
{
    int     size = s -> size;//bfd_section_size(s->owner, s);
    unsigned char * buf  = malloc(size);
    if( buf == NULL ) exit( EXIT_FAILURE ); //xmalloc()

//    if(!bfd_get_section_contents(s->owner, s, buf, 0, size)) {
//        free(buf);
//        return FALSE;
//    }
//    buf = s -> contents;
    size = SIZE;

    dinfo->section       = s;
    dinfo->buffer        = buf;
    dinfo->buffer_length = size;
    //dinfo->buffer_vma    = bfd_section_vma(s->owner, s);
    dinfo->buffer_vma    = bfd_section_vma( s );

    //printf("Allocated %d bytes for %s section\n: 0x%lX", size, s->name,
    //        dinfo->buffer_vma);
    return TRUE;
}

/*
 * Method of locating section from VMA taken from opdis.
 */
typedef struct {
    bfd_vma    vma;
    asection * sec;
} BFD_VMA_SECTION;

/*
 * Used to locate section for a vma.
 */
void vma_in_section(bfd * abfd, asection * s, void * data)
{
   BFD_VMA_SECTION * req = data;

   //printf( "f" );  fflush( stdout );
   if(req && req->vma >= s->vma &&
   //req->vma < (s->vma + bfd_section_size(abfd, s)) ) {
   req->vma < (s->vma + bfd_section_size( s )) )
   {
      //printf( "g" );  fflush( stdout );
      req->sec = s;
   }
}

void map_over_sections (bfd *abfd,
                        void (*operation) (bfd *, asection *, void *),
                        void *user_storage)
{
  asection *sect;
  unsigned int i = 0;

  for (sect = abfd->sections; sect != NULL; i++, sect = sect->next)
    (*operation) (abfd, sect, user_storage);

  if (i != abfd->section_count) /* Debugging */
    abort ();
}

/*
 * Locate and load section containing vma.
 */
bool load_section_for_vma(bfd * abfd, disassemble_info * dinfo,
        bfd_vma vma)
{
    BFD_VMA_SECTION req = {vma, NULL};
    map_over_sections(abfd, vma_in_section, &req);
    //printf( "e" );  fflush( stdout );

    if(!req.sec) {
        return FALSE;
    } else {
        return load_section(abfd, dinfo, req.sec);
    }
}

//void print_address_func(bfd_vma addr, struct disassemble_info *dinfo);
void record_label( dword addr );
//FILE* ipass = NULL;

/*
 * Start disassembling from entry point.
 */
bool disassemble_entry(bfd * abfd, disassemble_info * dinfo,
        disassembler_ftype disassembler)
{
    bfd_vma    vma = START;//= bfd_get_start_address(abfd);
    int passes[ 2 ];
    pipe( passes );
    ipass = fdopen( passes[ 0 ], "r" );
    opass = fdopen( passes[ 1 ], "w" );

    /* First locate and load the section containing the vma */
    if(load_section_for_vma(abfd, dinfo, vma)) {
        int size;

        /* Keep disassembling until signalled otherwise or error */
        while(true) {
            dinfo->insn_info_valid = 0;
            if( first_time )
            {
               record_label( START );
               //printf( ":\n" );  fflush( stdout );
               first_time = false;
            }
            size = disassembler(vma, dinfo); // print_insn()
            if( !stop_disassembling )
            {
               fprintf( opass, "\n" );  fflush( stdout );
               //printf("Disassembled %d bytes at 0x%lX\n", size, vma);
               begin_insn = true;
               label_insn = true;
            }
            if(size == 0 || size == -1 || stop_disassembling) {
                break;
            }

            vma += size;
        }

        free(dinfo->buffer);
        return TRUE;
    }

    return FALSE;
}

unsigned char* code = NULL;

int read_memory_func( bfd_vma memaddr, bfd_byte *myaddr, unsigned int length,
     struct disassemble_info *dinfo )
{
   unsigned int ulimit = START + SIZE;

//   printf( "7" );  fflush( stdout );
   if( memaddr < ulimit )
   {
      // label_insn ? yes label : dont label
      if( label_insn ) fprintf( opass, "x%08x:\n", memaddr );
      label_insn = false;
//      printf( "%08x\n", code );
      *myaddr = code[ memaddr - START ];
//      *myaddr = 0x90;
      return 0;
   }
   else
   {
      *myaddr = 0x90;
      stop_disassembling = TRUE;
      return 0;//length; // I think memaddr == myaddr.
   }
}

void memory_error_func( int status, bfd_vma memaddr, struct disassemble_info *dinfo )
{
}

struct label
{
   dword addr;
   struct label* next;
}* labels = NULL
,* here_label = NULL;

void record_label( dword addr )
{
   if( labels == NULL )
   {
      here_label = labels
       = malloc( sizeof( struct label ) );
      labels -> next = NULL;
      here_label -> addr = addr;
   }
   else
   {
      here_label
       = here_label -> next
       = malloc( sizeof( struct label ) );
      here_label -> next = NULL;
      here_label -> addr = addr;
   }
}

bool recorded_label( dword addr )
{
   struct label* here = labels;
   for(; here != NULL; here = here -> next )
   {
      if( here -> addr == addr )
         return true;
   }
   return false;
}

void print_address_func(bfd_vma addr, struct disassemble_info *dinfo)
{
   record_label( addr );
   fprintf( opass, "x%08x", addr );
}

int main(void)
{
   char  target_path[PATH_MAX] = {0};
   //bfd_init();
   /* Get path for the running instance of this program */
   get_target_path(target_path, ARRAY_SIZE(target_path));

   code = malloc( 80 );
   code[ 0 ] = 0x00;
   code[ 1 ] = 0x00;
   code[ 2 ] = 0xeb;
   code[ 3 ] = 0x00;
   code[ 4 ] = 0x00;
   code[ 5 ] = 0x00;
   SIZE = 6;

   struct bfd_section* text = malloc( sizeof( struct bfd_section ) );
   text -> name = ".text";
   text -> id = 0;
   text -> index = 0;
   text -> next = NULL;
   text -> prev = NULL;
   text -> flags = SEC_CODE | SEC_IN_MEMORY;
   text -> user_set_vma = 1;
   text -> linker_mark = 1;
   text -> linker_has_input = 1;
   text -> gc_mark = 1;
   text -> compress_status = 0;//2;
   text -> segment_mark = 1;
   text -> sec_info_type = 5;//3;
   text -> use_rela_p = 1;
   text -> sec_flg0 = 1;
   text -> sec_flg1 = 1;
   text -> sec_flg2 = 1;
   text -> sec_flg3 = 1;
   text -> sec_flg4 = 1;
   text -> sec_flg5 = 1;
   text -> vma = START; // 1 MiB.
   text -> lma = START;
   text -> size = SIZE;
   text -> rawsize = SIZE;
   text -> compressed_size = SIZE;
   text -> relax = NULL;
   text -> relax_count = 0;
   text -> output_offset = 0;
   text -> output_section = NULL;
   text -> alignment_power = 0;
   text -> relocation = NULL;
   text -> orelocation = NULL;
   text -> reloc_count = 0;
   text -> filepos = 0;
   text -> line_filepos = 0;
   text -> userdata = NULL;
   text -> contents = code;
   text -> lineno = NULL;
   text -> lineno_count = 0;
   text -> kept_section = NULL;
   text -> moving_line_filepos = 0;
   text -> target_index = 0;
   text -> used_by_bfd = NULL;
   text -> constructor_chain = NULL;
   text -> owner = abfd;
   text -> symbol = NULL;
   text -> symbol_ptr_ptr = NULL;
   text -> map_head.s = NULL;
   text -> map_tail.s = NULL;

   struct bfd_target* elf = malloc( sizeof( struct bfd_target ) );
   elf -> name = "none";
   elf -> flavour = bfd_target_elf_flavour;
   elf -> byteorder = BFD_ENDIAN_LITTLE;
   //...

   struct bfd_arch_info* cpu = malloc( sizeof( struct bfd_arch_info ) );
   cpu -> mach = bfd_mach_i386_i386_intel_syntax;
   cpu -> arch = bfd_arch_i386;
   //...

   abfd = malloc( sizeof( struct bfd ) ); //bfd_openr(target_path, NULL);
   abfd -> filename = "";
   abfd -> xvec = elf; // ???
   abfd -> iostream = NULL;
   abfd -> iovec = NULL;
   abfd -> lru_prev = NULL;
   abfd -> lru_next = NULL;
   abfd -> where = 0;
   abfd -> mtime = 0;
   abfd -> id = 0;
   abfd -> format = 3;
   abfd -> direction = 2; // change to intel later.
   abfd -> flags = 0;
   abfd -> cacheable = 1;
   abfd -> target_defaulted = 1;
   abfd -> opened_once = 1;
   abfd -> mtime_set = 1;
   abfd -> no_export = 1;
   abfd -> output_has_begun = 0; // 1?
   abfd -> has_armap = 0; // 1?
   abfd -> is_thin_archive = 0; // 1?
   abfd -> no_element_cache = 1; // 0
   abfd -> selective_search = 0; // was 1
   abfd -> is_linker_output = 1;
   abfd -> is_linker_input = 0; // 1?
   abfd -> plugin_format = 2; // ?
   abfd -> lto_output = 0; // was 1
   abfd -> lto_slim_object = 0; // was 1
   abfd -> plugin_dummy_bfd = NULL;
   abfd -> origin = 0;
   abfd -> proxy_origin = 0;
   abfd -> section_htab.table = NULL; // ?
   abfd -> section_htab.newfunc = NULL;
   abfd -> section_htab.memory = NULL;
   abfd -> section_htab.size = 0;
   abfd -> section_htab.count = 0;
   abfd -> section_htab.entsize = 0;
   abfd -> section_htab.frozen = 1;
   abfd -> sections = text; // depends on text
   abfd -> section_last = text;
   abfd -> section_count = 1;
   abfd -> archive_pass = 0; // was not sets.
   abfd -> start_address = START; // 1 MiB.
   abfd -> outsymbols = NULL;
   abfd -> symcount = 0;
   abfd -> dynsymcount = 0;
   abfd -> arch_info = cpu;
   abfd -> arelt_data = NULL;
   abfd -> my_archive = NULL;
   abfd -> archive_next = NULL;
   abfd -> archive_head = NULL;
   abfd -> nested_archives = NULL;
   abfd -> link.hash = NULL; // or -> next
   abfd -> tdata.elf_obj_data = NULL;
   abfd -> usrdata = NULL;
   abfd -> memory = NULL; // ...
   abfd -> build_id = NULL;


   //if(abfd != NULL && bfd_check_format(abfd, bfd_object))
   {
      disassembler_ftype disassembler = NULL;
                         disassembler = init_disasm(abfd, &dinfo);
      //printf( "c" );  fflush( stdout );
      dinfo.read_memory_func = read_memory_func;
      dinfo.memory_error_func = memory_error_func;
      dinfo.print_address_func = print_address_func;

      disassemble_entry(abfd, &dinfo, disassembler);
      //printf( "z" );  fflush( stdout );
      //bfd_close(abfd);
   }
   //FILE* _ipass = fdopen( ipass, "r" );
   int sz_buffer = 80;
   char* l_buffer = malloc( sz_buffer );
   fclose( opass );
   while( -1 != getline( &l_buffer, &sz_buffer, ipass ) )
   {
      if( l_buffer[ 0 ] == 'x' )
      {
         dword addr = 0;
         sscanf( l_buffer + 1, "%08x", &addr );
         //printf( "= %08x\n", addr );
         if( !recorded_label( addr ) )
            continue;
      }
      printf( "%s", l_buffer );
   }
   free( l_buffer );
   fclose( ipass );
//   free( code );
   free( text );
   free( cpu );
   free( elf );
   free( abfd );
//   printf( "\n" );  fflush( stdout );
   return EXIT_SUCCESS;
}