/* $Id: sp_template.c,v 1.5 2004/02/13 16:19:03 roesch Exp $ */
/* Snort Detection Plugin Source File Template */

/* sp_template 
 *
 * Purpose:
 *
 * Detection engine plugins test an aspect of the current packet and report
 * their findings.  The function may be called many times per packet with 
 * different arguments.  These functions are acccessed from the rules file
 * as standard rule options.  When adding a plugin to the system, be sure to 
 * add the "Setup" function to the InitPlugins() function call in 
 * plugbase.c!
 *
 * Arguments:
 *
 * This is the type of arguements that the detection plugin can take when
 * referenced as a rule option
 *
 * Effect:
 *
 * What the plugin does.
 *
 * Comments:
 *
 * Any comments?
 *
 */


/* stickydrop is only used in inline mode */
#ifdef GIDS


#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "mstring.h"
#include "plugin_enum.h"
#include "spp_stickydrop.h"
#include "sp_stickydrop.h"
/* 
 * don't forget to include the name of this file in plugbase.c! 
 */

/* 
 * setup any data structs here 
 */
//typedef struct _StickyDSp
//{
//    int stickyd_timeout;     
//    char stickyd_direction;
//} StickyDSp;

/* function prototypes go here */
void StickyDSpInit(char *, OptTreeNode *, int);
static void StickyDSpRuleParseFunction(char *, OptTreeNode *, StickyDSp *);
static int StickyDSpFunction(Packet *, struct _OptTreeNode *, 
        OptFpList *);

/*
 * 
 * Function: SetupTemplate()
 *
 * Purpose: Generic detection engine plugin template.  Registers the
 *          configuration function and links it to a rule keyword.  This is
 *          the function that gets called from InitPlugins in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupStickyDSp()
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("sticky-drop", StickyDSpInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: StickyDSp Setup\n"););
}


/*
 * 
 * Function: TemplateInit(char *, OptTreeNode *)
 *
 * Purpose: Generic rule configuration function.  Handles parsing the rule 
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 */
void StickyDSpInit(char *data, OptTreeNode *otn, int protocol)
{
    StickyDSp *stickydsp_d;
    OptFpList *ofl;

    if(!SppStickydIsRunning())
    {
        FatalError("dude, you can't have a sticky-drop plugin without the sticky-drop preproc\n");
    }
    stickydsp_d = (StickyDSp *) SnortAlloc(sizeof(StickyDSp));
    StickyDSpRuleParseFunction(data, otn, stickydsp_d);

    ofl = AddOptFuncToList(StickyDSpFunction, otn);
    ofl->context = (void *) stickydsp_d;
    otn->ds_list[PLUGIN_STICKYDSP]=(StickyDSp *)stickydsp_d;
}



/*
 * 
 * Function: TemplateRuleParseFunction(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *            td => pointer to the configuration storage struct
 *
 * Returns: void function
 *
 */
static void StickyDSpRuleParseFunction(char *data, OptTreeNode *otn, StickyDSp *sd) 
{
   char **toks;
   int numToks;
   char *direction;
   toks = mSplit(data, ",", 2, &numToks, 0);

      if(numToks > 2)
         FatalError("ERROR %s (%d): Bad arguments to sticky-drop: %s\n", file_name,
                 file_line, data);
  
           if(isdigit((char)toks[0][1]))
           {
               sd->stickyd_timeout = atoi(toks[0]);
           }
           else
           {
               FatalError("ERROR %s (%d): Bad arguments to sticky-drop: %s\n", file_name,
                     file_line, data);
           }

        
      if(numToks > 1)
      {
          direction = toks[1];

          while(isspace((int)*direction)) {direction++;}

          if(!strcasecmp(direction, "src"))
          {           
              sd->stickyd_direction = 0;
          }         
          else if(!strcasecmp(direction, "dst"))
          {                
              sd->stickyd_direction = 1;
          }
          else
          {
   
               FatalError("%s(%d):we need a direction either src or dst%s\n",file_name,file_line,toks[1]);
          }
      }

       mSplitFree(&toks, numToks);
}


/*
 * 
 * Function: TemplateDetectorFunction(char *, OptTreeNode *, OptFpList *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *            fp_list => pointer to the function pointer list current node
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 */
static int StickyDSpFunction(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
//    StickyDSp *sd;   /* ptr to the detection option's data */
//
//    sd = (StickyDSp *) fp_list->context;
//
//    AddIpToBlockTree(p, sd->stickyd_direction, sd->stickyd_timeout);
    return 1;
}


#endif /* GIDS */
