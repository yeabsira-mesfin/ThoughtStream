import PostList from "./components/PostList";
import MainHeader from "./components/MainHeader";
import { useState } from "react";

function App() {
  const [modalVisible, setModal] = useState(false); 

  function showModalHandler() {
    setModal(true); 
  }

  function hideModalHandler() {
    setModal(false); 
  }

  return (
    <>
      <MainHeader onCreatePost={showModalHandler} />
      <main>
        <PostList isPosting={modalVisible} onStopPosting={hideModalHandler} />
      </main>
    </>
  );
}

export default App;
