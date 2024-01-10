import React from "react";
import PropTypes from "prop-types";
import {
  Button,
  ButtonGroup,
  Fade,
  Spinner,
  Input,
  FormFeedback,
} from "reactstrap";
import { Formik, Field, ErrorMessage } from "formik";
import { MdCheck, MdClose, MdEdit } from "react-icons/md";

import {
  Loader,
  MultiSelectCreatableInput,
  addToast,
} from "@certego/certego-ui";

import { JobTag } from "../../common/JobTag";
import { useTagsStore } from "../../../stores/useTagsStore";

// constants
const onFormValidate = (values) => {
  const errors = {};
  if (!values.label) {
    errors.label = "Required";
  } else if (values.label.length < 4) {
    errors.label = "Min length 4";
  }
  return errors;
};

// components
function TagNew(inputVal) {
  return (
    <span>
      Create New Tag: &nbsp;
      <JobTag tag={{ label: inputVal, color: "#1655D3" }} />
    </span>
  );
}
export function TagSelectInput(props) {
  const { selectedTags, setSelectedTags } = props;

  // local state
  const [tagToEdit, setTagToEdit] = React.useState(undefined);
  const onTagEditSuccess = React.useCallback(() => {
    setTagToEdit(undefined);
    setSelectedTags([]);
  }, [setTagToEdit, setSelectedTags]);

  // api
  const [loading, error, allTags, fetchAll, createTag] = useTagsStore(
    React.useCallback(
      (state) => [
        state.loading,
        state.error,
        state.tags,
        state.list,
        state.create,
      ],
      [],
    ),
  );

  // side-effecs
  React.useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  // memo
  const options = React.useMemo(
    () =>
      allTags.length
        ? allTags.map((tag) => ({
            value: tag,
            label: <JobTag tag={tag} />,
            labelOptionExtra:
              tagToEdit?.id === tag.id ? (
                <TagForm
                  tagToEdit={tagToEdit}
                  onFormSuccess={onTagEditSuccess}
                />
              ) : (
                <MdEdit
                  className="center pointer"
                  title="edit"
                  onClick={() => setTagToEdit(tag)}
                />
              ),
          }))
        : [],
    [allTags, tagToEdit, setTagToEdit, onTagEditSuccess],
  );

  // dropdown input handlers
  const onCreateOption = async (inputVal) => {
    try {
      const newTag = await createTag(inputVal, "#1655D3");
      setSelectedTags([
        ...selectedTags,
        { value: newTag, label: <JobTag tag={newTag} /> },
      ]);
    } catch (err) {
      addToast("Failed!", err.parsedMsg.toString(), "danger");
    }
  };
  const onChange = (selectedOpts, { action }) => {
    if (action === "select-option" || action === "deselect-option") {
      setSelectedTags(selectedOpts);
    } else if (action === "clear") {
      setSelectedTags([]);
    }
  };

  return (
    <Loader
      loading={false} // handled by MultiSelectCreatableInput.isLoading
      error={error}
      render={() => (
        <MultiSelectCreatableInput
          id="scanform-tagsselectinput"
          isLoading={loading}
          options={options}
          value={selectedTags}
          onChange={onChange}
          onCreateOption={onCreateOption}
          isSearchable={!tagToEdit}
          menuIsOpen={tagToEdit ? true : undefined}
          formatCreateLabel={TagNew}
        />
      )}
    />
  );
}

function TagForm(props) {
  const { tagToEdit, onFormSuccess, ...rest } = props;

  const [updateTag, createTag] = useTagsStore(
    React.useCallback((state) => [state.update, state.create], []),
  );

  const onFormSubmit = React.useCallback(
    async (values, formik) => {
      try {
        const newTag = tagToEdit?.id
          ? await updateTag(tagToEdit.id, values)
          : await createTag(values.label, values.color);
        setTimeout(() => onFormSuccess(tagToEdit, newTag), 250); // fake delay for better UX
      } catch (error) {
        addToast("Failed!", error.parsedMsg.toString(), "danger");
      } finally {
        formik.setSubmitting(false);
      }
    },
    [tagToEdit, onFormSuccess, updateTag, createTag],
  );

  return (
    <Fade>
      <Formik
        validate={onFormValidate}
        initialValues={tagToEdit}
        onSubmit={onFormSubmit}
        validateOnChange
        {...rest}
      >
        {(formik) => (
          <div className="d-flex align-items-end">
            <div>
              <Field
                as={Input}
                autoFocus
                type="text"
                tabIndex="0"
                name="label"
                placeholder="label"
                bsSize="sm"
                invalid={formik.errors.label && formik.touched.label}
                className="w-100 bg-dark border-0 rounded-0"
              />
              <ErrorMessage component={FormFeedback} name="label" />
            </div>
            <Field
              as={Input}
              type="color"
              name="color"
              bsSize="sm"
              className="w-33 bg-dark border-0 rounded-0"
            />
            <ButtonGroup className="ms-1">
              <Button
                type="submit"
                disabled={!(formik.isValid || formik.isSubmitting)}
                color="tertiary"
                size="xs"
                onClick={formik.handleSubmit}
              >
                {formik.isSubmitting ? <Spinner /> : <MdCheck />}
              </Button>
              <Button
                disabled={formik.isSubmitting}
                color="tertiary"
                size="xs"
                onClick={() => onFormSuccess(undefined, undefined)}
              >
                <MdClose />
              </Button>
            </ButtonGroup>
          </div>
        )}
      </Formik>
    </Fade>
  );
}

TagSelectInput.propTypes = {
  selectedTags: PropTypes.array.isRequired,
  setSelectedTags: PropTypes.func.isRequired,
};

TagForm.propTypes = {
  tagToEdit: PropTypes.object,
  onFormSuccess: PropTypes.func.isRequired,
};

TagForm.defaultProps = {
  tagToEdit: { label: undefined, color: "#ffffff" },
};
