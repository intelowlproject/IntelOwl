from api_app.visualizers_manager.classes import (
    VisualizableBase,
    VisualizableTitle,
    logger,
)
from api_app.visualizers_manager.enums import VisualizableColor, VisualizableSize


# IMPORTANT! this function allows to handle the errors in the components render.
# You must define a function that returns a Visualizable then
# use this function as a decorator. Ex:
# @visualizable_error_handler_with_params("field1", VisualizableSize.S_2)
# def generate_field1(value):
# ...
# in case the generation of the field will raise an error
# this will handle it allowing to render the other components
def visualizable_error_handler_with_params(
    *errors_names: str,
    error_size: VisualizableSize = VisualizableSize.S_AUTO,
):
    def visualizable_error_handler(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as error:
                logger.exception(error)
                names = [func.__name__] if not errors_names else errors_names
                result = []
                for error_name in names:
                    result.append(
                        VisualizableTitle(
                            title=VisualizableBase(value=error_name),
                            value=VisualizableBase(value="error", color=VisualizableColor.DANGER),
                            size=error_size,
                        )
                    )
                if len(result) == 1:
                    return result[0]
                return result

        return wrapper

    return visualizable_error_handler
