FIND_PATH(POPT_INCLUDE_DIR NAMES popt.h popt/popt.h)
FIND_LIBRARY(POPT_LIBRARY NAMES popt)
SET(POPT_INCLUDE_DIRS ${POPT_INCLUDE_DIR})
SET(POPT_LIBRARIES ${POPT_LIBRARY})

# TODO: check popt version and functions
MARK_AS_ADVANCED(POPT_LIBRARIES POPT_INCLUDE_DIRS)
